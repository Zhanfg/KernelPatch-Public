# PatchNest Core：双后端底层重构（RFC v1）

状态：**研发中 / 不可刷入 / 未完成真机验收**  
基线：`Zhanfg/KernelPatch-Public@0bdf0094`  
工作分支：`refactor/dual-backend-runtime`  
核心独立仓：`Zhanfg/KernelPatch-Public`  
管理端仓：`Zhanfg/PatchNest`（`cli/` + `module/` + `kpms/`）

## 1. 必须实现的两个版本

| 项目 | A：Kernel Integrated | B：Image Patched |
|---|---|---|
| 核心来源 | PatchNest Core | 同一 PatchNest Core |
| 安装过程 | 将内核源码实现以 `CONFIG_PATCHNEST_CORE=y` 编译进内核，AK3 只分发该内核 | `kptools` 对受支持的内核镜像进行离线修补，把 freestanding runtime 的 `kpimg` 注入镜像 |
| 内核编译要求 | 必须有完整可编译源码与适配补丁 | 不要求重新编译目标内核，但需要兼容的镜像结构、ARM64 指令/KCFI 约束及符号解析 |
| 运行时承载 | 内核内建组件；不依赖 WebUI 或用户态守护进程存活 | 注入后的镜像内 runtime；不依赖 WebUI 或用户态守护进程存活 |
| KPM 管理 | 轻量 CLI / WebUI 调控制接口 | 同一 CLI / WebUI，动态选择 patched adapter |
| 更新内核 | 重新编译并打包 AK3 | 对新基线重测、重新修补 |
| 无法兼容 | 构建失败，不得伪装成成功 | 直接拒绝修补，不得强行写入 |
| 与其他 root 系统 | 显式能力协商，避免双重 su/hook | 显式能力协商，避免双重 su/hook |

**澄清**：AK3 是镜像打包与安装工具，不能替代内核编译阶段的链接。把现有 `kpimg` 复制进 AK3 ZIP 不等于方案 A。

## 2. 分层设计

```text
PatchNest WebUI / CLI              <- 非常薄的控制面，无需常驻
           |
      protocol v1                  <- include/patchnest/runtime_abi.h
           |
     authenticated adapter
       /             \
  kernel-native     image-patched  <- 后端特有初始化 / memory / hooks
       \             /
        KPM runtime                 <- ELF/relocations, lifecycle, events, safety
           |
       loaded KPMs
```

管理端先查询 `STATUS`，验证 ABI 主版本、`backend` 和真实能力位，**绝不通过「检测是否 root」推断内核支持 KPM**。后续管理操作：LIST、LOAD、UNLOAD、EVENT、READ_AUDIT。v1 禁止未定义 `flags`，请求必须校验大小上限、操作权限和字段边界。

### 核心内部接口（迁移目标）

1. `pn_elf_validate()`：严格长度/节区/符号/重定位校验，验证在任何解引用之前执行。
2. `pn_module_prepare()`：核验元数据与签名、准备内存权限、resolve 符号，但不发布模块。
3. `pn_module_activate()`：受控 init，成功后才进入公开模块表。
4. `pn_module_deactivate()`：先标记卸载并阻止新引用，等待进行中的控制/事件回调退出，再执行 exit、回收代码和数据。
5. `pn_event_dispatch()`：可拒绝已经卸载/隔离的模块；回调不持有不允许睡眠的锁。
6. `pn_safety_boot_guard()`：崩溃计数、安全模式、最后一次加载事务持久化；嵌入模块必须可隔离。
7. `pn_audit()`：记录启动来源、验证结果、模块生命周期与失败原因，必要时脱敏。

本阶段先修复现有 loader 的独立可确认错误；**上述新函数名是目标接口，不代表都已实现**。

### Kernel Integrated（A）的实现路径

- 引入 `kernel/patchnest/Kconfig` 与 `kernel/patchnest/Makefile`，支持 arm64 的 `bool` 型 built-in 构建；**不把当前 freestanding `kernel/base/*.S` 直接作为内核 `obj-y`**。它们预设了不同的链接、地址映射、符号解析与初始化时机。
- 创建 Linux native port：使用内核分配器、workqueue/mutex/RCU、内核已支持的安全内存权限与适用的 symbol API；必要的 hook 技术要按 GKI/CFI 版本分级，不允许全局关掉 KCFI 来凑兼容。
- 将 KPM 装载器从 root/hiding 逻辑里分离：KPM 能力默认独立于 SU；复用现有 ReSukiSU / KernelSU 时不得安装第二个 superuser/hook 栈。
- 模块嵌入采用 **构建期只读清单**：每个 KPM 有名称、大小、哈希、签名、加载阶段和隔离策略。嵌入更新需要重新编译或提供受信的后续部署路径；WebUI 不得声称能「运行时改写已编译内核中的只读 KPM」。
- 给 AK3 生成设备/构建身份清单，校验对应的 `Image`、DTB/DTBO、AVB、槽位和内核 ABI。出现不匹配直接停止安装。

### Image Patched（B）的实现路径

- 保持原有 `kpimg`、`kptools` 为兼容基础；在既有能力上引入 `patched adapter`，而非立即重写所有 ARM64 重定位/指令注入逻辑。
- 支持离线预检、原镜像备份、原子生成目标镜像、写入后比对、可回滚恢复。拒绝未知 ELF/boot header/KCFI 组合。
- 加载 KPM 时调用相同的安全策略和生命周期算法；静态嵌入与在线加载共享同一判定。
- 独立修补版应输出镜像或待刷入 ZIP；不直接对用户当前 boot 分区做隐式写入。

## 3. 统一安全规则

- 默认不启用未知的 KPM，嵌入包的信任链必须在安装前验证；签名策略不能仅依赖 WebUI。
- 所有修改操作都需真实调用者授权检查；**已授权普通 UID 不等于拥有全局策略/授予其他 UID 的权限**。
- 严禁在卸载 KPM 时释放仍被回调执行的代码；正确的引用保护/睡眠同步完成前，动态卸载不可被标记为稳定。
- 内核安全模式能禁止所有第三方 KPM，不得与系统其他 root 管理器相互打架。
- 不允许把 `.ko` 当作 `.kpm` 无条件兼容：必须分别验证重定位、导出符号、KCFI、许可证和生命周期。
- 不允许修补 `init_boot` 与 `boot` 的规则互换；A/B slots、AVB 与设备差异需单独处理。
- 运行时 idle 路径必须事件驱动，不增设每秒轮询的常驻用户态 daemon。

## 4. 阻塞与真实验收

已有真实负面测试：OnePlus 6 的 BakaSU v0.2 支持加载/嵌入指定 KPM，而 v0.3 加载/嵌入后会重启或掉入 recovery。**这不能简单归因于 PatchNest，也不能跳过回归测试。**

现有待修 P0: #6（授权升级）、#7（superkey 长度）、#8（列表信息泄漏）、#9（TOCTOU）、#10（KPM UAF）、#11（cred/ seccomp）、#12（回调 NULL）、#13（ELF）、#14（启动计数）、#15（RCU）。这些应在正式刷机前全部审计闭环。

验收门槛：

1. 代码级单元测试 + 负样本测试、UBSAN/KASAN（支持的测试内核）、静态检查。
2. A：至少一种实际 arm64 内核 Kbuild 编译和 AK3 打包成功，验证 KPM 加载/卸载、嵌入与重启。
3. B：原始镜像→修补→启动→KPM→重启→卸载/撤回→恢复原镜像，验证 A/B 两个槽位。
4. 两种后端测试一致的 ABI、错误码、安全模式和事件生命周期。
5. 真机分别执行正常场景、空指针/畸形 ELF、并发 unload/control、失败注入和已知 OP6 v0.3 回归。

## 5. 当前分支完成范围

- 已建立双后端的 **ABI v1 数据结构/能力标识**，不等于已经挂接到内核控制通道。
- 已修正现有 KPM loader 的几类独立风险：部分 ELF 边界、init/exit 空回调、模块枚举缓冲区、未知模块查询的 RCU 锁泄漏。
- 后续必须补齐：KPM 高并发引用/卸载协议，native port，两个实际 adapter，用户态 API 调用、Kbuild/AK3 构建和真机验证。
- **禁止发布可刷入稳定包或自动合并 `main`，直到这些条件完成。**

## 6. 版本与仓库治理

- Core 改动仅在本仓库 feature 分支；WebUI/CLI 改动将进入 `Zhanfg/PatchNest` 的对应 feature 分支。
- 不物理迁仓、不重命名、不改变默认分支、不删除历史 Release。
- 功能分支通过 Draft PR 审查；稳定版等真正 device gate 通过再考虑合并。
