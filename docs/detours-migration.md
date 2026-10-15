# Detours 迁移：x86 / x64

## 分支与依赖

`main` 的 `4461854` 只清理未使用的旧 hook 实现。后续迁移位于
`codex/detours-migration`，使用独立 worktree；稳定版修复仍提交到 `main`，
再合并或 cherry-pick 到迁移分支。验证完成后整体合并迁移分支，避免长期维护两个后端。

Detours 源码位于 `third_party/detours`，固定到 Microsoft 上游提交
`1dbd4ea281d73d478aa8d09a8b83fbd265f715f7`，使用 MIT 许可证。
上游源文件未修改，来源和许可证见该目录的 `UPSTREAM.txt`、`LICENSE.md`。
`Detours.props` 将 `detours.cpp`、`disasm.cpp`、`modules.cpp` 随调用项目编译，
沿用项目的架构、工具集和 CRT。旧的四个 `inlineHook_*.lib` 与 `inlinehook.h` 已删除。

本次仅迁移 Win32/x64 inline hook。DLL 注入、跨位数启动和现有代理策略沿用原实现；
没有添加 ARM64 或 ARM64EC 构建配置。

## 实现与生命周期

- `HookDispatch.h` 保存带调用约定的原函数指针。Detours 在安装时将其更新为 trampoline，
  卸载时恢复成原函数地址；不再修改占位 C++ 函数，也不再使用 `myAlloc4Bakcode`。
- `HookWinsock.cpp` 先解析本次需要的全部导出，再通过 `DetourHooks.cpp` 执行单次事务。
  任一准备步骤失败则中止事务；卸载失败时保留 hook 对象、配置和原函数指针。
- `DetourHooks.cpp` 收集当前进程的其他线程并登记到 Detours 事务，让 Detours 调整
  受影响线程的指令位置。调用者必须控制 trampoline 和回调对象的生命周期。
- `HookCallGate` 在修改 hook 前暂停新回调进入，并等待正在执行的回调退出。
  同一线程上的嵌套调用继续执行，避免阻止已有调用完成。等待超过 5 秒时返回失败，
  恢复原来的入口状态，调用者可稍后重试。不能在回调内部调用启停接口。
- 异步 socket 层使用稳定的 `Bypass_*` 转发函数，每次在入口保护范围内读取当前原函数指针，
  不再缓存 Detours trampoline 地址。
- `WSAIoctl` 返回的 `ConnectEx` / `WSASendMsg` 回调可能被应用长期缓存。
  因此其原函数指针跨启停保留，停止后直接调用原函数；首次进入安装流程时固定本 DLL，
  直到进程退出。`gp_UnhookWinsock` 会移除补丁并释放本次 hook 对象，但不会卸载 DLL。
  `DllMain` 的退出路径不再进行等待或 Detours 事务。

## 验证

在 Windows 10 x64（10.0.19045）、VS 2019 上验证：

- Win32/x64 Release 完整解决方案编译与现有单元测试。
- Win32/x64 Debug Hook DLL 编译（单独检查，未运行 Debug 端到端测试）。
- 相对 CALL、短/近条件跳转、x64 RIP 相对 LEA/MOV 的 trampoline 执行结果。
- 批量安装失败回滚、错误卸载后正确重试、原指针/原指令/页面保护恢复。
- 入口等待超时、嵌套调用、回调内启停拒绝、LastError 保留，以及四线程下 50 轮安装/卸载。
- Win32/x64 TCP/UDP 真实流量、精确流量统计、三轮 hook 启停，以及停止后调用缓存的扩展函数。
- 32→32、32→64、64→32、64→64 托管子进程/孙进程启动、SOCKS5 连接和 MSBuild 启动。
- IPv6 阻断、loopback 例外与仅 IPv4 的远程 DNS。

从仓库运行 `tests/run-detours-tests.ps1` 可复现以上 Release 回归。需要 VS 2019 的
v141_xp/v142、Windows SDK、项目所用 ATL/MFC，以及 PATH 中的 Go、64 位 Python
（含 psutil）、Rust/cargo/rustup；解决方案会构建已有的安全传输组件。
仅运行单元测试可使用 `tests/run-tests.ps1`。

尚未验证 XP/Windows 7、Windows 11 或 Windows on ARM 的运行环境。保留 v141_xp
编译配置不等于已经完成旧系统运行认证。线程快照也不能约束宿主在提交期间新建线程；
优先在启动阶段安装，停用时让应用进入空闲状态。此次没有扩展原有的 Winsock 多 provider
处理方式，扩展函数仍各保存一个原函数指针；第三方 provider 组合需要单独测试。
