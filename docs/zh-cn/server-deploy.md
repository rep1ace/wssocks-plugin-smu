# 服务端部署

本文说明如何在校内服务器上部署 wssocks 服务端，并通过 systemd 管理其运行状态。

服务端源码仓库：[wssocks](https://github.com/rep1ace/wssocks)

---

## 1. 安装 wssocks 服务端

### 方式 A：下载预编译二进制

从 [GitHub Releases](https://github.com/rep1ace/wssocks/releases) 下载对应平台的二进制文件，例如 Linux x86_64：

```bash
wget https://github.com/rep1ace/wssocks/releases/latest/download/wssocks-linux-amd64 -O wssocks
chmod +x wssocks
sudo mv wssocks /usr/local/bin/wssocks
```

### 方式 B：从源码编译

需要先安装 Go 1.18+：

```bash
git clone https://github.com/rep1ace/wssocks.git
cd wssocks
go build -o wssocks .
sudo mv wssocks /usr/local/bin/wssocks
```

验证安装：
```bash
wssocks --version
```

---

## 2. 手动启动（测试用）

```bash
wssocks server --addr :1088 --auth --auth_key YOUR_SECRET_KEY
```

- `--addr` 指定监听端口，确保该端口已在服务器防火墙中放行。
- `--auth` 启用连接鉴权，`--auth_key` 指定自定义密钥（不指定则自动生成随机密钥并打印到控制台）。

---

## 3. 使用 systemd 部署（推荐）

### 3.1 创建 systemd 服务文件

```bash
sudo nano /etc/systemd/system/wssocks.service
```

写入以下内容（按实际情况修改）：

```ini
[Unit]
Description=WSSocks Proxy Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/wssocks server --addr :1088 --auth --auth_key YOUR_SECRET_KEY
Restart=on-failure
RestartSec=5s
# 可选：以非 root 用户运行（推荐）
# User=nobody

[Install]
WantedBy=multi-user.target
```

> 将 `YOUR_SECRET_KEY` 替换为你设置的鉴权密钥，客户端填写的 **auth token** 需与此一致。  
> 端口 `1088` 可按需修改，同时需在服务器防火墙放行该端口。

### 3.2 启动并设置开机自启

```bash
# 重新加载 systemd 配置
sudo systemctl daemon-reload

# 设置开机自启
sudo systemctl enable wssocks

# 立即启动服务
sudo systemctl start wssocks
```

### 3.3 查看运行状态

```bash
sudo systemctl status wssocks
```

查看日志：
```bash
sudo journalctl -u wssocks -f
```

### 3.4 停止 / 重启

```bash
sudo systemctl stop wssocks
sudo systemctl restart wssocks
```

---

## 4. 客户端配置

服务端部署完成后，在 GUI 客户端中填写：

- **remote address**：`wss://your-server-host:1088`（若未配置 TLS，则使用 `ws://`）
- **auth token**：与服务端 `--auth_key` 一致的密钥

---

## 5. 可选：TLS 加密

若希望使用 TLS 加密传输，可在启动命令中添加证书参数（推荐使用 Let's Encrypt 申请证书）：

```bash
wssocks server --addr :1088 --auth --auth_key YOUR_SECRET_KEY \
  --tsl \
  --tls-cert-file /path/to/cert.pem \
  --tls-key-file /path/to/key.pem
```

客户端 **remote address** 相应改为 `wss://your-server-host:1088`。

也可以在 wssocks 前面套一层 nginx 反向代理来处理 TLS，详见 [wssocks README](https://github.com/rep1ace/wssocks#tslssl-support)。
