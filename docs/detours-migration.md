# Detours 迁移：x86 / x64

## 分支与依赖

迁移已通过 `e45f579` 合并到 `main`，保留依赖引入 `fb535c6`、后端替换
`8f80a84`、回归测试 `8d3ab7f` 三个提交。旧后端最后一个提交为 `4461854`，
使用附注标签 `pre-detours-migration` 保存，便于检出对照版本。
后续 Windows ARM64 原生适配单独评估，不改变此 x86/x64 基线。

Detours 源码位于 `third_party/detours`，固定到 Microsoft 上游提交
`1dbd4ea281d73d478aa8d09a8b83fbd265f715f7`，使用 MIT 许可证。
上游源文件未修改，来源和许可证见该目录的 `UPSTREAM.txt`、`LICENSE.md`。
`Detours.props` 将 `detours.cpp`、`disasm.cpp`、`modules.cpp` 随调用项目编译，
沿用项目的架构、工具集和 CRT。旧的四个 `inlineHook_*.lib` 与 `inlinehook.h` 已删除。

本次仅迁移 Win32/x64 inline hook。DLL 注入、跨位数启动和现有代理策略沿用原实现；
没有添加 ARM64 或 ARM64EC 构建配置。

旧 x64 后端使用入口前 5 字节填充区和入口处的 `EB F9` 短跳转。
当前 Detours 没有主动创建这种 patch-above 布局的接口；其 x86/x64 入口补丁
需要至少 5 字节完整指令或可用的函数尾填充。过短目标会导致本项目中止整批安装。
识别已有 OS hotpatch 的能力不等于支持创建该布局，这是已知的兼容性差异。

## 实现与生命周期

- `HookDispatch.h` 保存带调用约定的原函数指针。Detours 安装时将其更新为 trampoline；
  不再修改占位 C++ 函数，也不再使用 `myAlloc4Bakcode`。
- `HookWinsock.cpp` 在提交入口补丁之前准备配置、回调对象并解析全部导出，
  再通过 `InstallDetourHooks` 执行单次安装事务。准备失败中止事务；未安装成功的
  对象可以清理后重试，成功安装的对象、配置和跳板保持到进程结束。
- 安装流程仍有串行化锁，防止两个安装请求同时修改状态。此锁不进入网络调用热路径。
  同一进程重复调用 `gp_HookWinsock` 返回 `FALSE` / `ERROR_ALREADY_EXISTS`，不重装补丁。
- 安装器不枚举、不打开、不挂起宿主线程，也不调用 `DetourUpdateThread`。
  这样避免挂起持锁线程后，安装事务申请同一把锁造成的死锁。
  **事务不保证并发发布原子性**：首次安装时仍有入口指令改写、其他线程指令位置，
  以及入口已改写而 `Original_*` 指针尚未更新的窗口。优先在启动阶段安装；
  这些是明确接受的并发安装风险，功能回归通过不代表消除了风险。
- 移除 `HookCallGate` / `HookCallScope`，不再排空网络调用，也不在每次调用中维护
  全局活动计数、嵌套 TLS 或排空事件。请求管道、socket 表等业务锁及子进程创建 TLS 保留。
- 异步 socket 层保留轻量 `Bypass_*` 包装：已安装时调用稳定 trampoline，未安装时调用
  系统函数。包装本身不创建保护域、不等待全局调用门。
- 安装前固定 DLL；入口补丁、`CHookWinsock` 和应用缓存的 `ConnectEx` / `WSASendMsg`
  回调保持有效。`DllMain` 退出路径不进行等待或 Detours 卸载事务。
- `gp_UnhookWinsock` 保留导出和调用约定，但始终返回 `FALSE`，设置
  `ERROR_NOT_SUPPORTED`（50）。它不会卸载、修改配置、删除对象，也不会假装关闭成功。
  旧调用者必须检查返回值；不再支持进程存活期间的物理卸载。
- GUI 开始／停止沿用本地代理服务的启停流程，不新增宿主 hook 的逻辑开关。

## 验证

当前 Release 回归覆盖：

- Win32/x64 完整解决方案编译与现有单元测试。
- 相对 CALL、短/近条件跳转、x64 RIP 相对 LEA/MOV 的 trampoline 执行结果。
- 无效参数、重复绑定、批量准备失败中止与重试，以及页面保护恢复。
- 每个 Detours 用例在独立进程安装一次，安装完成后进行四线程持续调用；
  不把无挂起的首次安装竞态包装成已保证安全的测试。
- Win32/x64 TCP/UDP 真实流量与精确统计、安装失败重试、重复安装拒绝、
  显式卸载返回错误且入口补丁不变、拒绝卸载后继续使用缓存扩展回调与发送数据。
- 本地代理服务关闭、重启后，由新的客户端进程继续发送并验证统计。
- 32→32、32→64、64→32、64→64 托管子进程/孙进程启动、SOCKS5 连接和 MSBuild 启动。
- IPv6 阻断、loopback 例外与仅 IPv4 的远程 DNS。

从仓库运行 `tests/run-detours-tests.ps1` 可执行以上 Release 回归。需要 VS 2019 的
v141_xp/v142、Windows SDK、项目所用 ATL/MFC，以及 PATH 中的 Go、64 位 Python
（含 psutil）、Rust/cargo/rustup；解决方案会构建已有的安全传输组件。
仅运行单元测试可使用 `tests/run-tests.ps1`。

完整 E2E 应从未被其他 ProxyLane 代理的进程启动。Python 测试运行器保留对旧版外部
Hook DLL 的解除尝试，仅用于兼容既有开发环境；若继承的是不支持卸载的常驻版本，
测试会明确报错，不能忽略失败后混用两套 Hook。产品测试不再依赖新版本的卸载成功。

2026-10-16 常驻 hook 调整已在 Windows 10 x64 / VS 2019 通过上述 Win32/x64
Release 回归，日志位于 `build/qa/hook-lifecycle/regression.log`。未进行吞吐量基准测试，
不把移除同步操作表述为已测得的性能提升。

2026-10-15 合并后，已在原工程目录重新构建 Win32/x64 Release 并通过完整回归。
日志保存在 `build/qa/detours-merge`。运行中的另一套 ProxyLane 曾向测试服务和探针
注入第二份 Hook DLL，导致 UDP 超时；流量测试现与托管启动测试一样，仅解除一次性
Python 测试进程继承的 hook，再创建受控子进程，不修改用户正在运行的代理。
上述为原迁移时的验证记录。当前发行包只在根目录携带 `LICENSE-Detours.txt`，
不附带来源说明，也不创建 `third_party` 目录。
迁移 worktree 的构建产物及日志另存于 `build/detours-migration-archive`。

尚未验证 XP/Windows 7、Windows 11 或 Windows on ARM 的运行环境。保留 v141_xp
编译配置不等于已经完成旧系统运行认证。此次没有扩展原有的 Winsock 多 provider
处理方式，扩展函数仍各保存一个原函数指针；第三方 provider 组合需要单独测试。
