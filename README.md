<h1 align="center">ProxyLane</h1>

<p align="center">
  <strong>Windows 应用进程级透明代理 · HTTPS / QUIC 流量解密</strong><br>
  免 TUN · 独立代理配置 · 子进程自动继承 · 流量录制与离线回放
</p>

<p align="center">
  欢迎来 <a href="https://linux.do/t/topic/2980923">Linux.do</a>、<a href="https://v2ex.com/t/1242151">V2EX</a> 社区讨论
</p>

<p align="center">简体中文 | <a href="README_EN.md">English</a></p>

---

ProxyLane 是一款面向 Windows 的应用进程级透明代理工具。它通过进程注入和网络 API Hook，让指定程序的网络连接使用单独配置的代理，而不需要修改系统全局代理。

**也可以直接用来分析应用的加密流量：** 支持 HTTPS 与 QUIC v1 解密，查看 HTTP/1.1、HTTP/2、HTTP/3 请求响应及正文，并按进程录制、筛选和离线回放。选择 `NOPROXY` 即可在不使用外部代理的情况下进行监视与解密。

解密功能需使用 **64 位主程序**，按需启用并安装本地 CA；应用兼容性及操作步骤见 [流量监视与解密](#流量监视与解密)。

## 操作演示

![ProxyLane 操作演示](demo.gif)

## 使用场景

### 代理命令行工作区

首先启动代理（代理设置需已勾选“代理子进程”），然后打开一个在命令提示符，在 ProxyLane 的应用与进程中，选中新增的 `cmd.exe` 并点击“代理所选”按钮。此后从该命令行窗口启动的 `curl`、Git、Python、`pip`、包管理器及其他程序，都会自动继承当前代理设置，无需逐个添加程序，也不需要修改系统全局代理。

例如：

```bat
curl https://example.com
git clone https://github.com/example/project.git
pip install requests
python script.py
```


## 功能

- 对指定应用或进程透明代理
- 支持 HTTPS 与 QUIC v1 解密，查看 HTTP/1.1、HTTP/2、HTTP/3 请求响应与正文（64 位主程序）
- 支持按进程查看网络会话、DNS 查询响应及 Raw／Hex 数据
- 支持流量录制与离线回放，便于留存、排查和分析
- 支持代理配置管理和连接测试
- 支持 HTTP / SOCKS5 TCP 与 UDP 代理
- 支持进程规则和目标规则
- 支持直接拖入程序或快捷方式启动
- 提供运行日志和连接流量统计
- 提供 Win32 与 x64 版本
- 兼容 Windows XP 至 Windows 11

## 技术路线

ProxyLane 采用纯用户态的进程注入与 API Hook 技术，对应用程序的网络连接进行拦截和重定向，不安装或加载内核驱动，也不需要修改系统全局代理。

- 将与目标进程位数匹配的 Hook 模块注入用户选定的进程，拦截其网络 API，并将符合规则的 TCP、UDP 网络连接重定向到指定代理。
- 通过 Hook 监控进程创建行为。启用“代理子进程”后，每一级已注入进程都会继续监控其子进程，因此可以沿进程链处理多级子进程，并根据过滤规则决定是否继续注入。
- 对需要代理的子进程，Hook 模块的加载和初始化会在该子进程的主线程上下文中完成；初始化成功后才恢复主线程执行，使网络 Hook 在应用程序发起网络连接前就绪，从而可靠地拦截其后续网络行为。
- 主程序负责代理配置、过滤规则和日志展示，Hook 模块负责监控子进程创建及网络行为。整个过程均在用户态完成。
- 同时提供 Win32 和 x64 组件，兼容范围从 Windows XP 到 Windows 11。
- 32 位主程序及 Windows XP / Server 2003 保留主体代理功能，不支持数据监视、HTTPS 解密和 gonc 加密传输；支持这些功能的 64 位主程序可处理 32/64 位目标应用。

## 构建环境

- Visual Studio 2019
- Visual C++ v141_xp 工具集
- Windows 7.1A SDK
- Rust MSVC 工具链（64 位解密模块使用 1.88.0）

打开 `src/ProxyLane.sln`，选择 `Win32` 或 `x64` 平台后构建即可。Release 输出位于 `bin/` 目录。

### gonc TLS-PSK 加密传输

SOCKS5、HTTP10 和 HTTP11 配置都可以在“加密模式”中选择 `gonc TLS-PSK`，并填写与远端 gonc `:s5s` 服务一致的 PSK。SOCKS5 支持加密 TCP 与 UDP；HTTP10/HTTP11 使用加密的 HTTP CONNECT，仅支持 TCP，不需要在本机另外启动 gonc 客户端或标准代理中转。

远端 gonc 默认只启用 SOCKS5。若要让同一个 TLS-PSK 端口同时接受 SOCKS5 和 HTTP，请在内置服务参数中增加 `-http`，例如 `gonc -e ":s5s -u -http" -l -k -psk 123 -tls 1083`。

PSK 按初版设计以明文写入所选 profile 的 `PSK=` 字段，请妥善限制 `ProxyLane.ini` 的访问权限。标准（不加密）模式不加载加密组件。

加密传输由 64 位主程序中的 `ProxyLaneSecureTransport64.dll` 提供，也支持代理 32 位应用。32 位主程序保留普通代理功能，不支持加密传输。主程序及 Hook DLL 仍使用 `v141_xp` 构建，未选择加密模式时不会加载此 DLL。构建加密组件需要 Rust MSVC 工具链：

```bat
src\build-secure-transport.bat
```

该批处理会自动构建 Win32、x64 两个 Release 版本，并复制到 `bin/`。也可以直接运行底层 PowerShell 脚本：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build-secure-transport.ps1
```

### 流量监视与解密

64 位 ProxyLane 可以按进程查看已接管应用的网络会话，不需要应用使用系统代理。支持 HTTP/1.1、HTTP/2 的请求响应、正文解压，DNS 查询响应，以及普通 TCP/UDP 的 Raw、HexView 查看。HTTPS 解密不限定 443 端口；QUIC v1 解密也不限定应用名称或端口。

进入 **流量监视 → 解密选项**，按需启用 **解密 HTTPS** 或 **解密 QUIC**（两项默认关闭），首次使用按提示安装当前用户 CA，保存后再开始监视。目标应用需要重新建立连接；停止监视后停止新增解密和采集，已接管连接继续转发。QUIC 选项还会尝试放宽兼容的 Chromium 应用对可信本地/企业 CA 的额外限制，保留常规证书校验。修改 QUIC 选项后，请完全退出并重新运行目标应用；浏览器兼容修改持续到目标进程退出，停止监视不会撤回。浏览器兼容性仍需随版本验证。

只想监视、不使用外部代理时，选择 `NOPROXY`，无需填写地址和端口。启用需要的 TCP/UDP 接管，取消“禁止 UDP”，再接入目标应用。普通监视不需要 CA。使用独立信任库、证书固定或尚不支持的 QUIC 应用协议时，解密可能不可用；当前不保证覆盖所有 QUIC 应用及收发方式。

开启 QUIC 解密后，自动识别协商的应用协议，无需填写 ALPN。HTTP/3 按请求响应还原，其他协议按 Stream ID 查看原始明文；QUIC DATAGRAM 独立按报文展示，均支持 Raw／HexView 和录制。当前支持 QUIC v1，不支持 0-RTT 转发、连接迁移及 HTTP/3 扩展中的 WebTransport、CONNECT-UDP。

需要长时间留存、交给智能体分析时，在 **流量监视 → 选项 → 录制选项** 中启用 **保留录制文件**，设置保存位置、容量和磁盘预留空间，再开始监视。保留录制的勾选仅在本次运行有效；保存位置和容量设置会记住。会话信息、请求响应头和载荷持续保存，退出后仍可查看。达到容量上限或磁盘空间不足时会停止录制，不删除旧载荷，也不影响已有连接转发。

停止监视后，选择 **选项 → 查看已有录制…**，选择录制目录，即可重新浏览会话、筛选进程并查看 Raw／HexView，无需启动代理。正常离线浏览只读列表索引，详情按需加载。索引缺失或损坏时会询问是否重建，重建不修改原始请求和载荷。也可以直接把目录交给智能体分析，目录内附有格式说明。

## 分享代理配置

在代理设置页打开 **配置操作 ▾** 菜单，选择 **复制完整配置**，可复制当前界面的完整代理方案，包括尚未保存的修改、用户名、密码、PSK、网络选项、子进程规则和目标规则。配置码为一行 `proxylane://profile/v1/…` 文本；Base64URL 只是编码，持有配置码的人可以读取其中的凭据。

对方复制整行后选择 **配置操作 ▾ → 粘贴配置**，所有相关选项会自动填入，随后可保存或启动代理。重名配置会添加“（导入）”后缀；当前有未保存的修改时会先询问如何处理。代理正在运行时，粘贴不会立即改变运行设置，需要点击 **保存并应用**。全局选项、解密设置、CA、录制文件及最近应用不包含在代理配置码中。

展开配置下拉框时会重新读取配置名称列表，以反映其他实例的新增和删除；选中配置时读取最新设置。刷新列表不会覆盖当前编辑内容；当前配置被其他实例删除时，其界面内容会保留为未保存草稿。

## 界面语言

ProxyLane 内置简体中文和英文。默认跟随 Windows 界面语言，也可以在“关于与语言”页面选择语言；修改后在下次启动时生效。

全部可翻译文字保存在 UTF-8 语言目录中：

- `src/ProxyLane/locales/zh-CN.json`
- `src/ProxyLane/locales/en-US.json`

两份文件必须保持相同的键集合。`ProxyLane.rc` 只维护控件布局，语言目录作为 `RCDATA` 嵌入 EXE，因此发行包不需要附带外部语言文件。

修改翻译后可运行 `powershell -ExecutionPolicy Bypass -File .\scripts\check-locales.ps1` 检查语言键和资源文件。

## 打包发行版

先构建 Win32 与 x64 的 Release 版本，然后在项目根目录运行：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\package-release.ps1
```

脚本会从程序文件属性读取版本号，检查主程序与 Hook DLL 的版本是否一致，并生成 `dist/ProxyLane-版本-Windows.zip`。压缩包包含 Win32/x64 主程序、对应的 Hook DLL、64 位加密传输和 MITM DLL、样例配置、许可证以及中英文 README。测试和命令行辅助工具不进入发行包。

样例配置保存在 `examples/ProxyLane.ini`，打包后会以 `ProxyLane.ini` 放在压缩包根目录。

发行包只包含一个 `LICENSE`：首先是 ProxyLane 自身许可证，随后在 `Third-Party Software Licenses` 标题下汇总第三方许可证和相关声明。

“测试当前设置”使用 `[options]` 下的 `IPv6TestAddress` 作为 IPv6 出口探测地址；该值必须是 IPv6 字面地址，默认使用 `2001:4860:4860::8888`，探测端口为 TCP 53。

每个 profile 可使用 `BlockIPv6=1` 阻止被代理进程访问外部 IPv6 地址；IPv4、IPv4-mapped IPv6 和本机 `::1` 不受影响。界面中的“阻止 IPv6”默认关闭。

如需指定输出目录，可增加参数 `-OutputDirectory D:\releases`。

## 项目结构

- `src/ProxyLane`：MFC 桌面界面与应用逻辑
- `src/ProxyLaneHook`：进程注入与网络 Hook 模块
- `src/remotecode`：远程代码执行辅助模块
- `tests`：单元测试
- `examples`：样例配置
- `scripts`：发行包生成脚本
