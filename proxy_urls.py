#!/usr/bin/env python3
"""把多行 IP 转成 HTTP 代理地址。改下面三项后运行本文件即可。"""

from urllib.parse import quote

USERNAME = "username"
PASSWORD = "password"
PORT = 8080

IPS = """
1.1.1.1
2.2.2.2
"""


def main():
    user = quote(USERNAME, safe="")
    password = quote(PASSWORD, safe="")
    for line in IPS.splitlines():
        host = line.strip()
        if not host or host.startswith("#"):
            continue
        print("http://%s:%s@%s:%s" % (user, password, host, PORT))


if __name__ == "__main__":
    main()
