# VSCode Remote-SSH 连接校内服务器

VSCode 的 Remote-SSH 扩展可以让你直接在本地 VSCode 中编辑和运行远程服务器上的代码。在校外访问校内服务器时，需要借助 wssocks 客户端提供的 SOCKS5 代理（默认地址 `127.0.0.1:1080`）进行转发。

---

## 配置步骤

### 1. 安装 Remote-SSH 扩展

在 VSCode 的 **Extensions**（扩展）面板中搜索并安装 **Remote - SSH**。

### 2. 打开 SSH 配置文件

按 `Ctrl/Cmd + Shift + P`，输入 `remote`，选择 **Remote-SSH: Open SSH Configuration File…**，选择用户目录下的配置文件（通常为 `~/.ssh/config`）。

### 3. 添加服务器配置

根据你的操作系统，在配置文件中添加如下内容：

**macOS / Linux：**
```
Host myserver
    HostName your-server-host
    User your-username
    ProxyCommand nc -X 5 -x 127.0.0.1:1080 %h %p
```

**Windows（已安装 nmap/ncat）：**
```
Host myserver
    HostName your-server-host
    User your-username
    ProxyCommand ncat --proxy 127.0.0.1:1080 --proxy-type socks5 %h %p
```

**Windows（使用 Git Bash 自带的 connect）：**
```
Host myserver
    HostName your-server-host
    User your-username
    ProxyCommand connect -S 127.0.0.1:1080 %h %p
```

若 `connect` 命令报错，请使用完整路径：
```
    ProxyCommand "C:/Program Files/Git/mingw64/bin/connect.exe" -S 127.0.0.1:1080 %h %p
```

> 将 `your-server-host` 替换为实际的服务器地址，`your-username` 替换为你的登录用户名，`127.0.0.1:1080` 与客户端的 **socks5 address** 保持一致。

### 4. 连接服务器

在 VSCode 左侧边栏的 **Remote Explorer** 中，找到刚刚配置的主机条目，点击右侧的连接图标即可。首次连接时 VSCode 会自动在远程服务器上安装 VS Code Server，稍等片刻即可进入远程开发环境。

---

## 关于 Windows 环境准备

- **ncat**：随 [nmap](https://nmap.org/download.html) 一起安装，或 `winget install Nmap.Nmap`。
- **connect**：随 [Git for Windows](https://git-scm.com/download/win) 安装，位于 `Git/mingw64/bin/connect.exe`。

推荐使用 ncat 方式，与 macOS/Linux 行为更一致。
