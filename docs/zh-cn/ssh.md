# SSH 连接校内服务器

启动客户端并连接成功后（默认 SOCKS5 监听地址为 `127.0.0.1:1080`），可通过以下两种方式将 SSH 流量通过代理转发。

---

## 方法一：在终端模拟器软件中设置代理

许多终端模拟器（如 Tabby、MobaXterm、XShell、SecureCRT 等）支持在软件内部配置 SOCKS5 代理。进入对应软件的连接或会话设置，找到"代理"选项，选择代理类型为 **SOCKS5**，并填写代理服务器地址为 `127.0.0.1`、端口为 `1080`（即客户端的 socks5 address 设置值）。

配置完成后，直接在该终端软件中新建 SSH 连接即可，无需额外命令。

---

## 方法二：通过命令行或 `~/.ssh/config` 配置代理

### macOS / Linux

**命令行临时使用：**
```bash
ssh -o ProxyCommand='nc -X 5 -x 127.0.0.1:1080 %h %p' user@your-server-host
```

**写入 `~/.ssh/config`（推荐，一劳永逸）：**

编辑 `~/.ssh/config`，添加如下配置：
```
Host myserver
    HostName your-server-host
    User your-username
    ProxyCommand nc -X 5 -x 127.0.0.1:1080 %h %p
```

之后直接执行 `ssh myserver` 即可自动走代理。

> `nc` 为系统自带，`-X 5` 指定使用 SOCKS5 协议，`-x` 指定代理地址。

---

### Windows

Windows 系统原生不带 `nc`，有以下几种方式可选：

**方式 A：安装 netcat 后使用 `nc`（推荐）**

从 [nmap 官网](https://nmap.org/download.html) 安装 nmap（含 ncat），或通过 winget 安装：
```powershell
winget install Nmap.Nmap
```

安装后在 `~/.ssh/config` 中配置：
```
Host myserver
    HostName your-server-host
    User your-username
    ProxyCommand ncat --proxy 127.0.0.1:1080 --proxy-type socks5 %h %p
```

**方式 B：使用 Git Bash 自带的 `connect`**

若已安装 Git for Windows（Git Bash），可使用其自带的 `connect.exe`：

在 `~/.ssh/config` 中配置：
```
Host myserver
    HostName your-server-host
    User your-username
    ProxyCommand connect -S 127.0.0.1:1080 %h %p
```

或使用完整路径（部分 Windows 环境直接用 `connect` 会失败）：
```
    ProxyCommand "C:/Program Files/Git/mingw64/bin/connect.exe" -S 127.0.0.1:1080 %h %p
```

> 注意：`connect -S` 中 `-S` 表示 SOCKS 代理，`127.0.0.1:1080` 替换为实际的客户端监听地址。

---

以上配置中，`127.0.0.1:1080` 为客户端默认的 SOCKS5 监听地址，若在客户端中修改了 **socks5 address**，请对应替换。
