#!/usr/bin/env bash
# Authenticated HTTP proxy one-command installer.
#
#   wget -N --no-check-certificate https://raw.githubusercontent.com/cummingdarleen09-oss/HttpProxy/refs/heads/main/httpProxy.sh && bash httpProxy.sh username password
#
# Optional third argument is the listen port (default 8080).
set -euo pipefail

RAW_URL="https://raw.githubusercontent.com/cummingdarleen09-oss/HttpProxy/refs/heads/main/proxy.py"
SERVICE_NAME="httpproxy"

usage() {
  cat <<'EOF'
用法:
  bash httpProxy.sh <username> <password> [port]
  bash httpProxy.sh --status
  bash httpProxy.sh --stop
  bash httpProxy.sh --restart

一键部署:
  wget -N --no-check-certificate https://raw.githubusercontent.com/cummingdarleen09-oss/HttpProxy/refs/heads/main/httpProxy.sh && bash httpProxy.sh username password
EOF
}

if [[ "$(id -u)" -eq 0 ]]; then
  INSTALL_DIR="/opt/httpproxy"
else
  INSTALL_DIR="${HOME}/.httpproxy"
fi

ACTION="install"
USERNAME=""
PASSWORD=""
PORT="8080"

case "${1:-}" in
  -h|--help|help)
    usage
    exit 0
    ;;
  --status|--stop|--restart)
    ACTION="${1#--}"
    ;;
  "")
    usage
    exit 1
    ;;
  *)
    USERNAME="${1:-}"
    PASSWORD="${2:-}"
    PORT="${3:-8080}"
    if [[ -z "$USERNAME" || -z "$PASSWORD" ]]; then
      usage
      exit 1
    fi
    ;;
esac

if [[ "$ACTION" == "install" ]]; then
  case "${USERNAME}${PASSWORD}" in
    *$'\n'*|*$'\r'*)
      printf '用户名和密码不能包含换行\n' >&2
      exit 1
      ;;
  esac
  if ! [[ "$PORT" =~ ^[0-9]+$ ]] || (( PORT < 1 || PORT > 65535 )); then
    printf '端口必须是 1 到 65535 之间的数字\n' >&2
    exit 1
  fi
fi

PYTHON=""

python_ok() {
  "$PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 6) else 1)'
}

ensure_python() {
  if command -v python3 >/dev/null 2>&1; then
    PYTHON="$(command -v python3)"
    if python_ok; then
      return
    fi
    printf '找到的 python3 版本低于 3.6\n' >&2
    exit 1
  fi
  if [[ "$(id -u)" -ne 0 ]]; then
    printf '未找到 python3。请先安装 Python 3.6+，或使用 root 运行以便自动安装。\n' >&2
    exit 1
  fi
  printf '正在安装 python3...\n'
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    apt-get install -y python3 ca-certificates
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y python3 ca-certificates
  elif command -v yum >/dev/null 2>&1; then
    yum install -y python3 ca-certificates
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache python3 ca-certificates
  elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm python ca-certificates
  else
    printf '无法识别包管理器，请手动安装 python3\n' >&2
    exit 1
  fi
  PYTHON="$(command -v python3)"
  python_ok
}

use_systemd() {
  [[ "$(id -u)" -eq 0 ]] && command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]
}

stop_nohup() {
  local pidfile="$INSTALL_DIR/httpproxy.pid"
  if [[ ! -f "$pidfile" ]]; then
    return
  fi
  local pid
  pid="$(cat "$pidfile" 2>/dev/null || true)"
  if [[ -n "${pid}" ]] && kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    sleep 0.3
    if kill -0 "$pid" 2>/dev/null; then
      kill -9 "$pid" 2>/dev/null || true
    fi
  fi
  rm -f "$pidfile"
}

stop_proxy() {
  if use_systemd && [[ -f "/etc/systemd/system/${SERVICE_NAME}.service" ]]; then
    systemctl stop "$SERVICE_NAME" || true
  fi
  stop_nohup
}

status_proxy() {
  if [[ ! -f "$INSTALL_DIR/config.json" ]]; then
    printf '尚未安装。目录不存在: %s\n' "$INSTALL_DIR"
    exit 1
  fi
  if use_systemd && [[ -f "/etc/systemd/system/${SERVICE_NAME}.service" ]]; then
    systemctl --no-pager --full status "$SERVICE_NAME" || true
  elif [[ -f "$INSTALL_DIR/httpproxy.pid" ]]; then
    local pid
    pid="$(cat "$INSTALL_DIR/httpproxy.pid" 2>/dev/null || true)"
    if [[ -n "${pid}" ]] && kill -0 "$pid" 2>/dev/null; then
      printf '运行中 pid=%s\n' "$pid"
    else
      printf '未运行\n'
    fi
  else
    printf '未运行\n'
  fi
  HP_CONFIG="$INSTALL_DIR/config.json" "$PYTHON" - <<'PY'
import json, os
with open(os.environ["HP_CONFIG"], "r", encoding="utf-8") as handle:
    data = json.load(handle)
print("监听: %s:%s" % (data.get("bind", "0.0.0.0"), data.get("port")))
print("账号: %s" % data.get("username"))
PY
}

copy_program() {
  mkdir -p "$INSTALL_DIR"
  local script_dir
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  if [[ -f "$script_dir/proxy.py" ]]; then
    cp "$script_dir/proxy.py" "$INSTALL_DIR/proxy.py"
  else
    HP_URL="$RAW_URL" HP_DEST="$INSTALL_DIR/proxy.py" "$PYTHON" - <<'PY'
import os, ssl, urllib.request
url = os.environ["HP_URL"]
dest = os.environ["HP_DEST"]
request = urllib.request.Request(url, headers={"User-Agent": "httpproxy-installer"})
try:
    response = urllib.request.urlopen(request, timeout=60)
except Exception:
    response = urllib.request.urlopen(request, timeout=60, context=ssl._create_unverified_context())
payload = response.read()
if not payload.startswith(b"#!/"):
    raise SystemExit("downloaded proxy.py does not look like the proxy program")
with open(dest, "wb") as handle:
    handle.write(payload)
PY
  fi
  chmod 755 "$INSTALL_DIR/proxy.py"
}

write_config() {
  HP_CONFIG="$INSTALL_DIR/config.json" \
  HP_USER="$USERNAME" \
  HP_PASS="$PASSWORD" \
  HP_PORT="$PORT" \
  "$PYTHON" - <<'PY'
import json, os
path = os.environ["HP_CONFIG"]
data = {
    "username": os.environ["HP_USER"],
    "password": os.environ["HP_PASS"],
    "port": int(os.environ["HP_PORT"]),
    "bind": "0.0.0.0",
}
with open(path, "w", encoding="utf-8") as handle:
    json.dump(data, handle, ensure_ascii=False, indent=2)
    handle.write("\n")
os.chmod(path, 0o600)
PY
}

open_firewall() {
  if [[ "$(id -u)" -ne 0 ]]; then
    return
  fi
  if command -v ufw >/dev/null 2>&1; then
    if ufw status 2>/dev/null | grep -q "Status: active"; then
      ufw allow "${PORT}/tcp" || true
    fi
  fi
  if command -v firewall-cmd >/dev/null 2>&1; then
    if firewall-cmd --state >/dev/null 2>&1; then
      firewall-cmd --permanent --add-port="${PORT}/tcp" || true
      firewall-cmd --reload || true
    fi
  fi
}

start_proxy() {
  stop_proxy
  if use_systemd; then
    cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=Authenticated HTTP proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
ExecStart=$PYTHON $INSTALL_DIR/proxy.py --config $INSTALL_DIR/config.json
Restart=on-failure
RestartSec=2
LimitNOFILE=65535
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    systemctl restart "$SERVICE_NAME"
    if ! systemctl is-active --quiet "$SERVICE_NAME"; then
      systemctl --no-pager --full status "$SERVICE_NAME" || true
      exit 1
    fi
    return
  fi
  nohup "$PYTHON" "$INSTALL_DIR/proxy.py" --config "$INSTALL_DIR/config.json" >>"$INSTALL_DIR/httpproxy.log" 2>&1 &
  echo $! > "$INSTALL_DIR/httpproxy.pid"
  local attempt=0
  while (( attempt < 20 )); do
    if HP_PORT="$PORT" "$PYTHON" - <<'PY'
import os, socket, sys
sock = socket.socket()
sock.settimeout(0.3)
try:
    sock.connect(("127.0.0.1", int(os.environ["HP_PORT"])))
except Exception:
    sys.exit(1)
finally:
    sock.close()
PY
    then
      return
    fi
    if ! kill -0 "$(cat "$INSTALL_DIR/httpproxy.pid")" 2>/dev/null; then
      printf '代理进程启动失败，日志如下:\n' >&2
      tail -n 40 "$INSTALL_DIR/httpproxy.log" >&2 || true
      exit 1
    fi
    attempt=$((attempt + 1))
    sleep 0.2
  done
  printf '代理已启动但端口尚未就绪，请查看 %s\n' "$INSTALL_DIR/httpproxy.log" >&2
  exit 1
}

print_banner() {
  local ips encoded
  ips="$(HP_PORT="$PORT" "$PYTHON" - <<'PY'
import os, socket, urllib.request
port = os.environ["HP_PORT"]
addresses = []
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect(("8.8.8.8", 80))
    addresses.append(sock.getsockname()[0])
    sock.close()
except Exception:
    pass
try:
    request = urllib.request.Request("https://api.ipify.org", headers={"User-Agent": "httpproxy-installer"})
    with urllib.request.urlopen(request, timeout=4) as response:
        public = response.read().decode("ascii").strip()
    if public and public not in addresses:
        addresses.append(public)
except Exception:
    pass
if not addresses:
    addresses.append("127.0.0.1")
print("\n".join(addresses))
PY
)"
  encoded="$(HP_USER="$USERNAME" HP_PASS="$PASSWORD" "$PYTHON" - <<'PY'
import os
from urllib.parse import quote
print("%s:%s" % (quote(os.environ["HP_USER"], safe=""), quote(os.environ["HP_PASS"], safe="")))
PY
)"
  printf '\nHTTP 代理已启动\n'
  printf '目录: %s\n' "$INSTALL_DIR"
  printf '监听: 0.0.0.0:%s\n' "$PORT"
  printf '账号: %s\n' "$USERNAME"
  printf '\n客户端示例:\n'
  local ip
  local old_ifs="$IFS"
  IFS='
'
  for ip in $ips; do
    [[ -z "$ip" ]] && continue
    printf '  curl -x http://%s@%s:%s https://example.com\n' "$encoded" "$ip" "$PORT"
    printf '  export http_proxy=http://%s@%s:%s\n' "$encoded" "$ip" "$PORT"
    printf '  export https_proxy=http://%s@%s:%s\n' "$encoded" "$ip" "$PORT"
    printf '\n'
  done
  IFS="$old_ifs"
  if use_systemd; then
    printf '查看日志: journalctl -u %s -f\n' "$SERVICE_NAME"
  else
    printf '查看日志: tail -f %s/httpproxy.log\n' "$INSTALL_DIR"
  fi
  printf '停止服务: bash %s --stop\n' "$0"
}

case "$ACTION" in
  status)
    ensure_python
    status_proxy
    ;;
  stop)
    stop_proxy
    printf '已停止\n'
    ;;
  restart)
    ensure_python
    if [[ ! -f "$INSTALL_DIR/config.json" ]]; then
      printf '尚未安装，无法重启\n' >&2
      exit 1
    fi
    PORT="$(HP_CONFIG="$INSTALL_DIR/config.json" "$PYTHON" - <<'PY'
import json, os
with open(os.environ["HP_CONFIG"], "r", encoding="utf-8") as handle:
    print(json.load(handle)["port"])
PY
)"
    start_proxy
    printf '已重启，端口 %s\n' "$PORT"
    ;;
  install)
    ensure_python
    copy_program
    write_config
    open_firewall
    start_proxy
    print_banner
    ;;
esac
