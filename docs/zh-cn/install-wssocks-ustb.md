# wssocks 下载安装
由于已经部署好了 wssocks 服务端了，实际上这里可以只需要安装 wssocks 客户端就行。
对服务器部署感兴趣的可以参见 github 文档([https://github.com/rep1ace/wssocks#server-side](https://github.com/rep1ace/wssocks#server-side))，自行搭建搭建 wssocks 服务端。

另外，由于 USTB 校内网络需要通过 vpn 访问，这里的 wssocks 客户端是需要包含 vpn 插件 ([wssocks-plugin-ustb](https://github.com/rep1ace/wssocks-plugin-smu/))的。
为方便，我们把这个**包含该插件**的 wssocks 客户端叫为 **wssocks-ustb** 。

## wssocks-ustb 下载安装
wssocks-ustb 客户端及其插件的源码可在 [github](https://github.com/rep1ace/wssocks-plugin-smu) 获取。  
同时，也提供了预编译好的多种客户端，可在 [github release](https://github.com/rep1ace/wssocks-plugin-smu/releases) 
或者 [https://osdn.net/projects/wssocks-ustb/](https://osdn.net/projects/wssocks-ustb/) 下载。  
注：前者是稳定版，后者是 night-release，如果最新的稳定版还未释放出来，可使用 night-release 版本。

其中：
- client-ui-macOS-*.zip 和 client-ui-windows-amd64.exe 分别是 macOS 和 windows 上通用的 GUI wssocks-ustb 客户端（基于 [fyne](https://fyne.io) 构建）。自 v0.7.0 版本开始，macOS 系统上原生支持 arm64（M1/M2/M3等） 和 x64 （Intel）两种架构（之前的版本只原生支持x64平台，在 arm64 架构上运行需要通过 Rosetta 2 转译实现）。  
- wssocks-ustb-client-macOS-*.app.zip 是基于 swiftui 构建的 macOS wssocks-ustb 客户端，更符合 macOS 设计风格。自v0.7.0 版本开始，原生支持 arm64（M1/M2/M3等） 和 x64 （Intel）两种架构（之前的版本只原生支持x64平台，在 arm64 架构上运行需要通过 Rosetta 2 转译实现）。  
- 而 wssocks-ustb-{OS}-{ARCH} 是命令行版本，如果你是极客，可以下载改版本，命令行的参数使用可参见 [相关文档](https://github.com/rep1ace/wssocks-plugin-smu/blob/master/docs/zh-cn/README.md) 或者 **help** 子命令。

以下示例以 GUI 版本进行说明。

另外，需要注意的是，https://osdn.net/ 网站可能加载不出来的文件列表，需要准备好梯子 (下载文件本身不需要梯子🪜)。
