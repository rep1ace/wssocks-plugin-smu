# wssocks-plugin-smu

[![GitHub all releases](https://img.shields.io/github/downloads/rep1ace/wssocks-plugin-smu/total?color=brightgreen)](https://github.com/rep1ace/wssocks-plugin-smu/releases)
[![Release](https://github.com/rep1ace/wssocks-plugin-smu/actions/workflows/release.yml/badge.svg)](https://github.com/rep1ace/wssocks-plugin-smu/actions/workflows/release.yml)
![license](https://badgen.net/github/license/rep1ace/wssocks-plugin-smu)

**wssocks-plugin-smu** 是 [wssocks](https://github.com/rep1ace/wssocks) 的一个插件，用于在校外访问 SMU 校内网络（包括 SSH 连接服务器、VSCode Remote-SSH 等）。

本项目 fork 自 [genshen/wssocks-plugin-ustb](https://github.com/genshen/wssocks-plugin-ustb)，在原有基础上适配了 SMU 的 VPN 系统。感谢原作者的工作。

wssocks 是一个基于 WebSocket 协议的 SOCKS5 代理工具，同样 fork 自 [genshen/wssocks](https://github.com/genshen/wssocks) 并有所改进，详见：https://github.com/rep1ace/wssocks

---

## 客户端

提供以下几种客户端形式：

| | cli | client-ui | swiftui-client |
| -- | -- | --- | ------ |
| 截图 | - | ![client ui](./docs/zh-cn/resource/client.webp) | ![swiftui](./docs/zh-cn/resource/macos-client.webp) |
| 说明 | 命令行版本，支持全平台 | 基于 [fyne](https://fyne.io) 构建的跨平台 GUI 客户端 | 基于 SwiftUI 构建的 macOS 原生客户端 |
| 支持平台 | Windows x64, macOS x64/arm64, Linux x64/arm64 | Windows x64, macOS x64/arm64 | macOS x64/arm64 |

### 安装 cli 客户端

```bash
go install github.com/rep1ace/wssocks-plugin-smu/wssocks-ustb@latest
wssocks-ustb --help
```

或从 [GitHub Releases](https://github.com/rep1ace/wssocks-plugin-smu/releases) 下载对应平台的二进制文件（文件名格式：`wssocks-ustb-$OS-$ARCH`）。

### 安装 GUI 客户端（client-ui）

从 [GitHub Releases](https://github.com/rep1ace/wssocks-plugin-smu/releases) 下载，文件名格式：`client-ui-$OS-$ARCH`。

---

## 快速开始

### 服务端（校内服务器上）

```bash
wssocks server --addr :1088 --auth --auth_key YOUR_SECRET_KEY
```

推荐使用 systemd 管理服务端进程，详见[服务端部署文档](docs/zh-cn/server-deploy.md)。

### 客户端（本机）

GUI 版本直接打开即可，填写服务端地址和 auth token 后点击 Start。

CLI 版本：
```bash
wssocks-ustb client --remote=wss://your-server --key YOUR_SECRET_KEY --vpn-enable --vpn-host=your-vpn-host
```

---

## 文档

中文文档：[docs/zh-cn](docs/zh-cn/README.md)

主要内容：
- [客户端下载安装](docs/zh-cn/install-wssocks-ustb.md)
- [客户端使用说明](docs/zh-cn/wssocks-client.md)
- [SSH 连接校内服务器](docs/zh-cn/ssh.md)
- [VSCode Remote-SSH](docs/zh-cn/vscode-remote-ssh.md)
- [服务端部署](docs/zh-cn/server-deploy.md)
