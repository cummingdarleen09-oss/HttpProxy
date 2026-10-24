#!/usr/bin/env python3
"""Authenticated HTTP proxy.

Speaks the HTTP proxy protocol: absolute-form requests and CONNECT tunnels.
Every request must carry a Proxy-Authorization Basic credential.
"""

import argparse
import base64
import hmac
import http.client
import ipaddress
import json
import logging
import re
import select
import socket
import socketserver
import sys
from urllib.parse import urlsplit

HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "proxy-connection",
}

METADATA_HOSTS = {
    "metadata.google.internal",
    "metadata.goog",
}

METADATA_IPS = {
    ipaddress.ip_address("100.100.100.200"),
    ipaddress.ip_address("fd00:ec2::254"),
}

METHOD_RE = re.compile(r"[A-Za-z][A-Za-z0-9!#$%&'*+.^_`|~-]{0,63}\Z")
MAX_HEADER_BYTES = 64 * 1024
RELAY_IDLE_SECONDS = 300
IO_TIMEOUT = 120


class ProxyError(Exception):
    def __init__(self, status, reason, body):
        super().__init__(reason)
        self.status = status
        self.reason = reason
        self.body = body


class BlockedDestination(ProxyError):
    def __init__(self):
        super().__init__(403, "Forbidden", b"destination is not allowed\n")


def configure_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def load_settings(argv):
    parser = argparse.ArgumentParser(description="HTTP proxy with Basic authentication")
    parser.add_argument("-u", "--username", help="proxy username")
    parser.add_argument("-p", "--password", help="proxy password")
    parser.add_argument("--port", type=int, help="listen port (default 8080)")
    parser.add_argument("--bind", help="listen address (default 0.0.0.0)")
    parser.add_argument("--config", help="JSON file with username, password, port, and bind")
    args = parser.parse_args(argv)

    username = args.username
    password = args.password
    port = args.port
    bind = args.bind

    if args.config:
        with open(args.config, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        username = username or data.get("username")
        password = password or data.get("password")
        if port is None and data.get("port") is not None:
            port = int(data["port"])
        bind = bind or data.get("bind")

    if port is None:
        port = 8080
    if not bind:
        bind = "0.0.0.0"
    if not username or not password:
        parser.error("username and password are required")
    if any(char in "\r\n\x00" for char in username + password):
        parser.error("username and password cannot contain control characters")
    if not 1 <= int(port) <= 65535:
        parser.error("port must be between 1 and 65535")
    return username, password, bind, int(port)


def header_values(headers, name):
    return [value for key, value in headers if key.lower() == name]


def header_value(headers, name):
    values = header_values(headers, name)
    return values[0] if values else None


def hop_by_hop_names(headers):
    names = set(HOP_BY_HOP)
    for value in header_values(headers, "connection"):
        for part in value.split(","):
            item = part.strip().lower()
            if item:
                names.add(item)
    return names


def destination_blocked(host, port):
    normalized = host.lower().rstrip(".")
    if normalized in METADATA_HOSTS:
        return True
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip in METADATA_IPS or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            return True
    return False


def parse_connect_target(target):
    if target.startswith("["):
        end = target.find("]")
        if end <= 1:
            raise ValueError("invalid IPv6 target")
        host = target[1:end]
        rest = target[end + 1 :]
        if rest == "":
            port = 443
        elif rest.startswith(":") and rest[1:].isdigit():
            port = int(rest[1:])
        else:
            raise ValueError("invalid IPv6 port")
    elif target.count(":") > 1:
        raise ValueError("IPv6 targets must use [address]:port")
    elif ":" in target:
        host, port_text = target.split(":", 1)
        if not port_text.isdigit():
            raise ValueError("invalid port")
        port = int(port_text)
    else:
        host = target
        port = 443
    if not host or "/" in host or any(char.isspace() for char in host):
        raise ValueError("invalid host")
    if not 1 <= port <= 65535:
        raise ValueError("invalid port")
    return host, port


def decode_basic(value):
    if not value:
        return None
    scheme, _, token = value.strip().partition(" ")
    if scheme.lower() != "basic" or not token:
        return None
    token = "".join(token.split())
    token += "=" * ((-len(token)) % 4)
    try:
        decoded = base64.b64decode(token)
        text = decoded.decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    username, separator, password = text.partition(":")
    if separator != ":":
        return None
    return username, password


def credentials_match(presented, expected_user, expected_password):
    if presented is None:
        return False
    username, password = presented
    user_ok = hmac_compare(username, expected_user)
    pass_ok = hmac_compare(password, expected_password)
    return user_ok and pass_ok


def hmac_compare(left, right):
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def read_until_headers(sock):
    data = b""
    while b"\r\n\r\n" not in data and b"\n\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            return None
        data += chunk
        if len(data) > MAX_HEADER_BYTES:
            raise ProxyError(431, "Request Header Fields Too Large", b"headers too large\n")
    if b"\r\n\r\n" in data:
        head, rest = data.split(b"\r\n\r\n", 1)
        return head, rest
    head, rest = data.split(b"\n\n", 1)
    return head, rest


def parse_request_head(head):
    text = head.decode("iso-8859-1", "replace")
    lines = []
    for line in text.split("\n"):
        if line.endswith("\r"):
            line = line[:-1]
        lines.append(line)
    if not lines or not lines[0]:
        raise ProxyError(400, "Bad Request", b"empty request\n")
    parts = lines[0].split(" ")
    if len(parts) != 3 or not parts[2].startswith("HTTP/"):
        raise ProxyError(400, "Bad Request", b"malformed request line\n")
    method, target, version = parts
    if not METHOD_RE.match(method):
        raise ProxyError(400, "Bad Request", b"invalid method\n")
    headers = []
    for line in lines[1:]:
        if not line:
            continue
        if ":" not in line:
            raise ProxyError(400, "Bad Request", b"malformed header\n")
        name, value = line.split(":", 1)
        name = name.strip()
        value = value.strip()
        if not name or "\r" in value or "\n" in value:
            raise ProxyError(400, "Bad Request", b"malformed header\n")
        headers.append((name, value))
    return method, target, version, headers


def request_body_mode(headers):
    if header_values(headers, "transfer-encoding") and header_values(headers, "content-length"):
        raise ProxyError(400, "Bad Request", b"ambiguous request body\n")
    transfer = ",".join(header_values(headers, "transfer-encoding")).replace(" ", "").lower()
    if transfer:
        if transfer != "chunked":
            raise ProxyError(400, "Bad Request", b"unsupported transfer encoding\n")
        return "chunked", None
    length_values = header_values(headers, "content-length")
    if not length_values:
        return "none", 0
    if len(set(length_values)) != 1 or not length_values[0].isdigit():
        raise ProxyError(400, "Bad Request", b"invalid content length\n")
    return "fixed", int(length_values[0])


class ByteReader(object):
    def __init__(self, sock, initial):
        self.sock = sock
        self.buf = initial or b""

    def read(self, size):
        while len(self.buf) < size:
            chunk = self.sock.recv(max(4096, size - len(self.buf)))
            if not chunk:
                break
            self.buf += chunk
        data = self.buf[:size]
        self.buf = self.buf[size:]
        return data

    def readline(self):
        while b"\n" not in self.buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                break
            self.buf += chunk
        if b"\n" not in self.buf:
            line = self.buf
            self.buf = b""
            return line
        line, self.buf = self.buf.split(b"\n", 1)
        return line + b"\n"


def open_upstream(scheme, host, port):
    if scheme == "https":
        connection = http.client.HTTPSConnection(host, port, timeout=IO_TIMEOUT)
    else:
        connection = http.client.HTTPConnection(host, port, timeout=IO_TIMEOUT)
    connection.connect()
    return connection


def send_chunked_body(connection, reader):
    while True:
        line = reader.readline()
        if not line:
            raise ProxyError(400, "Bad Request", b"incomplete chunked body\n")
        size_text = line.strip().split(b";", 1)[0]
        try:
            size = int(size_text, 16)
        except ValueError:
            raise ProxyError(400, "Bad Request", b"invalid chunk size\n")
        if size == 0:
            while True:
                trailer = reader.readline()
                if trailer in (b"\r\n", b"\n", b""):
                    break
            connection.send(b"0\r\n\r\n")
            return
        remaining = size
        while remaining:
            chunk = reader.read(min(65536, remaining))
            if not chunk:
                raise ProxyError(400, "Bad Request", b"incomplete chunked body\n")
            connection.send(("%x\r\n" % len(chunk)).encode("ascii") + chunk + b"\r\n")
            remaining -= len(chunk)
        delimiter = reader.readline()
        if delimiter not in (b"\r\n", b"\n"):
            raise ProxyError(400, "Bad Request", b"invalid chunk delimiter\n")


def send_fixed_body(connection, sock, initial, length):
    if len(initial) >= length:
        if length:
            connection.send(initial[:length])
        return
    if initial:
        connection.send(initial)
    remaining = length - len(initial)
    while remaining:
        chunk = sock.recv(min(65536, remaining))
        if not chunk:
            raise ProxyError(400, "Bad Request", b"incomplete request body\n")
        connection.send(chunk)
        remaining -= len(chunk)


def stream_upstream_response(client, upstream, method):
    reason = (upstream.reason or "OK").replace("\r", " ").replace("\n", " ")
    skip = set(HOP_BY_HOP)
    connection_header = upstream.getheader("Connection")
    if connection_header:
        for part in connection_header.split(","):
            item = part.strip().lower()
            if item:
                skip.add(item)
    header_lines = []
    has_length = upstream.length is not None
    for key, value in upstream.getheaders():
        lowered = key.lower()
        if lowered in skip or lowered == "transfer-encoding":
            continue
        if lowered == "content-length" and not has_length:
            continue
        if "\r" in value or "\n" in value:
            continue
        header_lines.append(("%s: %s\r\n" % (key, value)).encode("iso-8859-1", "replace"))
    client.sendall(("HTTP/1.1 %s %s\r\n" % (upstream.status, reason)).encode("iso-8859-1", "replace"))
    for line in header_lines:
        client.sendall(line)
    client.sendall(b"Connection: close\r\n\r\n")
    if method == "HEAD" or upstream.status in (204, 304):
        return
    if has_length:
        remaining = upstream.length
        while remaining:
            chunk = upstream.read(min(65536, remaining))
            if not chunk:
                break
            client.sendall(chunk)
            remaining -= len(chunk)
        return
    while True:
        chunk = upstream.read(65536)
        if not chunk:
            break
        client.sendall(chunk)


def relay(client, remote, initial):
    if initial:
        remote.sendall(initial)
    client.settimeout(None)
    remote.settimeout(None)
    sockets = [client, remote]
    try:
        while True:
            readable, _, errored = select.select(sockets, [], sockets, RELAY_IDLE_SECONDS)
            if errored or not readable:
                break
            for current in readable:
                try:
                    data = current.recv(65536)
                except OSError:
                    return
                if not data:
                    return
                target = remote if current is client else client
                try:
                    target.sendall(data)
                except OSError:
                    return
    except (OSError, ValueError):
        return


class ProxyHandler(socketserver.BaseRequestHandler):
    def setup(self):
        self.connection = self.request
        self.connection.settimeout(30)
        self.responded = False
        try:
            self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass

    def finish(self):
        try:
            self.connection.close()
        except OSError:
            pass

    def handle(self):
        try:
            self.dispatch()
        except ProxyError as exc:
            if not self.responded:
                try:
                    self.send_simple(exc.status, exc.reason, exc.body)
                except OSError:
                    pass
            logging.info("%s rejected: %s", self.client_address[0], exc.reason)
        except socket.timeout:
            if not self.responded:
                try:
                    self.send_simple(408, "Request Timeout", b"request timeout\n")
                except OSError:
                    pass
            logging.info("%s timeout", self.client_address[0])
        except Exception:
            logging.exception("request from %s failed", self.client_address[0])
            if not self.responded:
                try:
                    self.send_simple(502, "Bad Gateway", b"bad gateway\n")
                except OSError:
                    pass

    def dispatch(self):
        loaded = read_until_headers(self.connection)
        if loaded is None:
            return False
        head, rest = loaded
        method, target, _version, headers = parse_request_head(head)
        if not self.authorized(headers):
            self.send_simple(
                407,
                "Proxy Authentication Required",
                b"proxy authentication required\n",
                extra=b'Proxy-Authenticate: Basic realm="HttpProxy"\r\n',
            )
            logging.info("%s %s %s -> 407", self.client_address[0], method, target)
            return
        self.connection.settimeout(IO_TIMEOUT)
        if method == "CONNECT":
            self.handle_connect(target, rest)
            return
        self.handle_http(method, target, headers, rest)

    def authorized(self, headers):
        presented = decode_basic(header_value(headers, "proxy-authorization"))
        return credentials_match(presented, self.server.username, self.server.password)

    def send_simple(self, status, reason, body, extra=b""):
        self.responded = True
        payload = body or b""
        extra_text = extra.decode("ascii") if extra else ""
        message = (
            "HTTP/1.1 %s %s\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "Content-Length: %s\r\n"
            "Connection: close\r\n"
            "%s"
            "\r\n"
        ) % (status, reason, len(payload), extra_text)
        self.connection.sendall(message.encode("ascii") + payload)

    def handle_connect(self, target, rest):
        try:
            host, port = parse_connect_target(target)
        except ValueError:
            raise ProxyError(400, "Bad Request", b"invalid connect target\n")
        if destination_blocked(host, port):
            raise BlockedDestination()
        try:
            remote = socket.create_connection((host, port), timeout=20)
        except OSError as exc:
            logging.info("%s CONNECT %s -> 502 (%s)", self.client_address[0], target, exc)
            raise ProxyError(502, "Bad Gateway", b"connect failed\n")
        remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            self.responded = True
            self.connection.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            logging.info("%s CONNECT %s:%s -> 200", self.client_address[0], host, port)
            relay(self.connection, remote, rest)
        finally:
            remote.close()

    def handle_http(self, method, target, headers, rest):
        parsed = urlsplit(target)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ProxyError(400, "Bad Request", b"proxy requests require an absolute URL\n")
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if destination_blocked(host, port):
            raise BlockedDestination()
        path = parsed.path or "/"
        if parsed.query:
            path = "%s?%s" % (path, parsed.query)
        mode, length = request_body_mode(headers)
        expect = header_value(headers, "expect") or ""
        expect_continue = "100-continue" in expect.lower()
        upstream = None
        try:
            upstream = open_upstream(parsed.scheme, host, port)
            upstream.putrequest(method, path, skip_accept_encoding=True)
            skip = hop_by_hop_names(headers)
            skip.update({"host", "content-length", "expect"})
            for name, value in headers:
                if name.lower() in skip:
                    continue
                upstream.putheader(name, value)
            if mode == "fixed":
                upstream.putheader("Content-Length", str(length))
            elif mode == "chunked":
                upstream.putheader("Transfer-Encoding", "chunked")
            upstream.endheaders()
            if expect_continue:
                self.connection.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
            reader = ByteReader(self.connection, rest)
            if mode == "chunked":
                send_chunked_body(upstream, reader)
            elif length:
                send_fixed_body(upstream, self.connection, rest, length)
            response = upstream.getresponse()
            self.responded = True
            stream_upstream_response(self.connection, response, method)
            logging.info("%s %s %s -> %s", self.client_address[0], method, target, response.status)
        except ProxyError:
            raise
        except OSError as exc:
            logging.info("%s %s %s -> 502 (%s)", self.client_address[0], method, target, exc)
            raise ProxyError(502, "Bad Gateway", b"upstream failed\n")
        finally:
            if upstream is not None:
                upstream.close()


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 128


def serve(username, password, bind, port):
    server = ThreadedTCPServer((bind, port), ProxyHandler)
    server.username = username
    server.password = password
    logging.info("HTTP proxy listening on %s:%s", bind, port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logging.info("shutting down")
    finally:
        server.server_close()
    return 0


def main(argv):
    configure_logging()
    try:
        username, password, bind, port = load_settings(argv)
    except SystemExit:
        raise
    except Exception as exc:
        logging.error("%s", exc)
        return 1
    try:
        return serve(username, password, bind, port)
    except OSError as exc:
        logging.error("failed to bind %s:%s: %s", bind, port, exc)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
