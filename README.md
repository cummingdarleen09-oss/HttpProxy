# HttpProxy

带 Basic 认证的 HTTP 代理。账号和密码从命令行传入，适合在服务器上一键安装。程序只使用 Python 3.6+ 标准库，同时支持普通 HTTP 转发和 `CONNECT` 隧道。

## 一键部署

```bash
wget -N --no-check-certificate https://raw.githubusercontent.com/cummingdarleen09-oss/HttpProxy/refs/heads/main/httpProxy.sh && bash httpProxy.sh username password
```

第三个参数是端口，默认 `8080`：

```bash
bash httpProxy.sh username password 3128
```

以 root 运行时安装到 `/opt/httpproxy`，并在 systemd 可用时注册 `httpproxy` 服务。普通用户运行时安装到 `~/.httpproxy`，由后台进程监听。

## 客户端

`https_proxy` 的值仍然使用 `http://`，因为这是访问代理本身的协议，目标网站的 HTTPS 走 `CONNECT` 隧道。

```bash
curl -x http://username:password@SERVER:8080 https://example.com
export http_proxy=http://username:password@SERVER:8080
export https_proxy=http://username:password@SERVER:8080
```

没有账号密码的请求会收到 `407 Proxy Authentication Required`。

## 管理

```bash
bash httpProxy.sh --status
bash httpProxy.sh --restart
bash httpProxy.sh --stop
```

root 安装后也可以使用：

```bash
systemctl status httpproxy
journalctl -u httpproxy -f
```

## 手动运行

```bash
python3 proxy.py --username username --password password --port 8080
```

## 说明

代理默认监听 `0.0.0.0`。请使用足够长的密码。客户端到代理这一段的 Basic 认证不会被 TLS 保护，代理应部署在你自己的服务器上，密码不要使用在其他网站上的口令。

为降低云主机被用来访问实例元数据的风险，代理拒绝链路本地地址以及常见云元数据地址。
