# WkDefender v0.1.0

WkDefender 是一个技术验证性 EDR 项目，采用 **"用户层系统服务 Agent + 内核驱动"** 混合架构。内核层集成进程/线程/镜像/对象/注册表回调、ETW、Minifilter 文件过滤、Syscall 检测和 ALPC 等实现遥测；用户层包含可执行文件分析、内存扫描（YARA）、进程系谱图、因果图、MITRE ATT&CK 映射和 SQLite 持久化等。

## Ⅰ. 核心架构总览

WkDefender 采用分层决策模型，其层级如下：

| 层级 | 名称 | 职责 |
|------|------|------|
| L0 | 内核硬实时 | 回调监控 / 白名单过滤 / 权威进程副本（WKD_PROCESS） |
| L1 | 内核软实时 | 静态特征和动态行为采集 / 分级异步或同步阻塞敏感操作 |
| L2 | 用户态 Agent | 复杂分析：IOC/IOA 深度判定 / 进程系谱图 / 因果图 / 攻击链 / MITRE ATT&CK 映射 |

内核驱动与用户层 Agent 通信链路：ALPC(+SectionView共享视图)、FltMessage 和 ETW。

---

### i) 内核驱动（WkDefender@driver/）

> KMDF / C 实现，Minifilter AntiVirus 类，Altitude 385210。

#### 入口与构建

| 文件路径 | 作用 |
|----------|------|
| `WkDefender@driver\WkdEntry.c` | 驱动入口 DriverEntry / DriverUnload，子系统初始化 |
| `WkDefender@driver\WkDefender.inf` | 驱动安装配置（Minifilter 类、Altitude、ALPC 主通道 + FLT YARA 端口） |
| `WkDefender@driver\WkDefender@driver.vcxproj` | VS 工程文件（Debug/Release × x64/ARM64） |

#### 核心子系统

| 子目录/文件 | 作用 |
|-------------|------|
| `AccessControl\SelfProtectionEngine` | 驱动自保护引擎 (流水线编排器)；当前子系统正在向 **通用访问控制** 引擎方向迁移  |
| `AccessControl\CallbackProtection` | 回调完整性检测（SHA-256 + MDL 恢复） |
| `AccessControl\AntiDebug` / `AntiUnload` / `IntegrityMonitor` / `RegistryProtection` | 反调试、防卸载、完整性监控、注册表保护 |
| `AccessControl\SelfProtectionCompat` | 自保护兼容层 |
| `AnalysisEngine\` | 内核侧分析流水线编排：`AnalysisEngine` 主编排 + `IoaEngine` + `IocEngine`（含 IocSyscall/IocThread/IocHandle/IocImage/IocProcess/IocAppControl 子类等） |
| `Callbacks\` | 内核回调注册：进程通知、线程通知、镜像加载通知、对象回调、注册表回调、文件系统通知 |
| `Common\` | 工具库：HashMap、HashSet、DynamicArray、Lookaside 池、PeriodicTimer、BCryptUtils、ExportParser、PeParser、PeCallbacks、Utils、Constants.h |
| `Common\Exempts\` | 内核豁免子系统（Exempts 门面 / ExemptsManager 存储 / ExemptPid / ExemptPath） |
| `ETW\ETWProvider` | 内核 ETW 提供者 |
| `FileSystem\` | Minifilter 文件过滤编排器：PreCreate/PreWrite/PostWrite/PreSetInformation/PreAcquireSection 回调、文件备份引擎、文件扫描、命名管道监控、USB 设备控制、进程文件上下文 |
| `Include\` | 公共头文件：FileSystem.h、Memory/MemoryIntegrity.h、Process/WkdProcess.h、Process/DefensiveEvasion.h |
| `Memory\` | 内存检测族：AMSI Bypass 检测、Shellcode 检测、注入检测、堆喷（HeapSpray）、ROP 检测、Sections 追踪、内存区域验证、内存扫描、内存完整性、内存监控 |
| `Notification\AlpcService` | ALPC 服务端（生产者-消费者模型） |
| `Notification\MessageQueue` / `MessageSync` | 驱动侧消息队列与同步 |
| `Notification\NotificationHandler` / `NotificationManager` | 通知分发与协议管理（与 Agent 侧 WkDefenderHeader.h 同步） |
| `Object\ObjectManager` | 全局对象注册管理 🔄️ |
| `Process\ProcessMonitor.c` | 基于 PsSetCreateProcessNotifyRoutine 维护权威进程表（WKD_PROCESS） |
| `Process\ProcessPairContext` | 父子进程上下文关联（供行为分析使用） |
| `Process\HollowingDetector` | 进程镂空（Process Hollowing）内联检测 |
| `Process\ProcessModuleTracker` | 进程模块加载追踪 |
| `Process\HandleScanner` | 句柄扫描 |
| `Syscall\SyscallMonitor` | 系统调用监控（ETW 拦截） |
| `Syscall\SyscallHijack` + `SyscallTrampoline.asm` | 系统调用挂钩引擎（汇编蹦床） |
| `Syscall\SyscallAggregation` / `SyscallContextCache` / `SyscallService` | Syscall 事件聚合、上下文缓存与分发 |
| `ThreatScoring\` | 内核侧威胁评分引擎 |

---

### ii) 用户态 Agent（WkDefender@agent/）

#### 入口与核心

| 文件路径 | 作用 |
|----------|------|
| `WkDefender@agent\main.c` | 主程序：12 步有序初始化（Storage / IOA / IOC / PolicyEngine / NotificationService / ProcessManager / CGE 编排器 / ALPC 路由等） |
| `WkDefender@agent\DefendTypes.h` | 全 Agent 公共类型基础：节点/边类型、128 位 InteractionBitmap 行为标志、FSM 模式、威胁分类/置信度/响应动作枚举 |
| `WkDefender@agent\WkDefenderHeader.h` | 与驱动同步的 ALPC 线格式消息协议（WKD_MESSAGE_TYPE 全集） |
| `WkDefender@agent\ScanManager.c/h` | 扫描编排层：排除 → SHA256 → 缓存 → 豁免 → ImageAnalyzer |
| `WkDefender@agent\process_manager.c/h` | 进程管理与处置引擎（8 级升级终止链、进程树终止、Watchdog 瓦解） |
| `WkDefender@agent\log_manager.c/h` | SQLite 日志管理 |
| `WkDefender@agent\system_manager.c/h` / `tools.c/h` | 系统信息采集与通用工具 |

#### IOC 引擎（IOC\）

| 模块 | 作用 |
|------|------|
| `IocEngine` / `IocScanner` | IOC 判定主编排与扫描驱动 |
| `IocMatcher\` | 规则匹配（Match） |
| `IocYaraScanner` | YARA 规则扫描器 |
| `IocKnownDll` / `IocCertUtils` | 已知 DLL 基线 / 证书校验工具 |
| `IocScriptScanner` / `IocPolymorphicDetector` | 脚本扫描 / 多态恶意代码检测 |
| `IocZeroDayDetector` | 零日未知样本聚类 |
| `IocEmulationEngine` / `IocSandboxAnalyzer` | 模拟执行 / 沙箱行为分析 |
| `IocArchiveScanner` / `IocRegistryVector` | 压缩包扫描 / 注册表攻击向量 |
| `IocProcessEnrich` | 进程上下文富化 |
| `PEAnalyzer\` | PE 解析族：PeParser / PeReader / PeLazy / PeUnpack / PeValidate |
| `ImageAnalyzer\` | 镜像分析三级六件套流水线 |
| `Signature\` | 签名验证族：Verifier / Details / Catalog / Cache / Reputation |

#### IOA 引擎（IOA\）

| 模块 | 作用 |
|------|------|
| `IoaCarsalGraph` | 因果关系图（核心数据结构） |
| `IoaEngine` | 行为分析主编排 |
| `IoaEdgeAggregate` / `IoaProcessPair` | 边聚合 / 进程对关系 |
| `IoaThreatScorer` / `IoaGraphRingBuffer` / `IoaPersistQueue` | 威胁评分 / 图环形缓冲 / 持久化队列 |
| `IoaInjectionClassifier` / `IoaMitreDetection` | 注入分类 / MITRE 映射 |
| `Tier1\` | 单事件规则 + 速率分析 + 语义进化（Tier1Engine / IoaRateAnalyzer / T1ShellcodeDetect） |
| `Tier2\` | FSM 多路归并 + 回溯（IoaFsmEngine / IoaTier2Backtrack） |
| `Tier3\` | 因果倒推 + 攻击链（CausalInference / CausalAnalyzer / Tier3Engine / T3AttackChain / Tier3Forensics / IoaGraphMatcher / IoaGraphWalker） |
| `PatternDetector\` | 8 个模式检测器（ROP / HEAP / JIT / LPE / KED / SPD / BufferOverflow 等） |
| `IoaRansomwareDetect` 等 | 勒索/持久化/C2/凭据/规避/外传/横向/堆喷/ROP/VAD 检测器，未接入主流水线 |

#### 编排与策略

| 模块 | 作用 |
|------|------|
| `Orchestrator\Engine` | CGE 主编排层 |
| `Orchestrator\VerdictEngine` | 中央判定层：多引擎加权融合（IOC / Tier1 / Tier2 / Tier3 / 行为） |
| `PolicyEngine\` | 策略引擎：告警去重 + 规则评估 + 序列规则（PolicyRules.h） |

#### 事件采集与通信

| 模块 | 作用 |
|------|------|
| `Notification\AlpcService` | ALPC 客户端（对接驱动） |
| `Notification\pipe_server` / `msg_queue` | 命名管道服务器 / 消息队列 |
| `Notification\EventParser` / `EventArchive` | 遥测事件解析 / 归档 |
| `Notification\NotificationService` | 通知服务（对接 NotifierHelper / UI） |
| `Notification\YaraScanPort` | YARA FLT 端口（驱动下发文件扫描） |
| `ETW\EtwConsumer` | ETW 事件消费者 |

#### 分析与检测域

| 模块 | 作用 |
|------|------|
| `Process\ProcessTree` | 进程谱系树 |
| `Process\ProcessSnapshot` / `ProcessThread` / `ProcessModule` | 进程快照 / 线程 / 模块（WKD_MODULE 权威副本） |
| `Process\DllInjectionDetector` / `ProcessHollowingDetector` / `ReflectiveInjectionDetector` | DLL 注入 / 进程镂空 / 反射式注入检测 |
| `Registry\RegistrySubsystem` | 注册表五引擎门面 |
| `Registry\PersistenceDetector`（The Watchman） | 持久化检测 |
| `Registry\RegistryAnalyzer`（The Deep Inspector） | 注册表深度分析 |
| `Registry\RegistryMonitor`（The Gatekeeper） | 注册表实时监控 |
| `Registry\StartupAnalyzer`（The Boot Guard） | 启动项分析 |
| `Registry\SystemSettingsMonitor`（The Config Guardian） | 系统设置监控 |
| `AccessControl\` | 用户态自保护：AccessControlEngine / AntiDebug / MemoryProtection / ProcessProtection / RegistryProtection |
| `AntiEvasio\` | 反规避检测族：调试器规避 / 环境规避 / 加壳检测 / 进程规避 / 沙箱规避 / 时间规避 |
| `FileSystem\DirectoryMonitor` | RDCW 目录监控 |
| `FileSystem\FileAnalyzer` / `FileLockManager` / `MountPointMonitor` | 文件分析 / 文件锁管理 / 挂载点监控 |
| `Memory\MemoryScan` / `MemorySignature` | 用户态内存扫描（AC 自动机 + YARA 导入） |
| `Driver\Install` | 驱动安装模块 |

#### 存储与支撑

| 模块 | 作用 |
|------|------|
| `Storage\StorageEngine` | 分层存储：Hot 内存 / Warm SQLite / Cold 归档 |
| `Storage\YaraRule` | YARA 规则存储 |
| `Common\` | 工具库：Utils / FileUtils / BCrypUtils / HashMap / PathUtil / TextSanitize / YaraUtils / YaraProtocol.h / TitaniumLimits.h |
| `Common\Exempts\` | 豁免子系统：门面 + Hash / Path / Cert / Injection / Process / Push 六维判定 |
| `External\sqlite3\` | SQLite 第三方库 |
| `External\openssl\lib\` | OpenSSL 链接库 |
| `External\yara\include\lib\` | YARA 引擎库 |
| `Include\` | 内部头文件：FileSystem/FileAnalyzer.h、Process/InjectionDetector.h |

---

## Ⅲ. MITRE ATT&CK 覆盖

+ Execution(TA0002)：T1047(Windows管理规范, WMI) 🔄️、T1059(命令和脚本解释器)、T1106(原生API调用)、T1129(共享模块) 🔄️、T1559(进程间通信)、T1569(系统服务) 🔄️等；
+ Persistence(TA0003)：T1053(计划任务/作业) 🔄️、T1078(有效账户) 🔄️、T1098(账户操纵) 🔄️、T1112(注册表修改)、T1136(创建账户) 🔄️、T1137(Office 应用程序启动) 🔄️、T1176 (软件扩展) 🔄️、T1542 (预启动引导) 🔄️、T1543(创建或修改系统进程)、T1546(事件触发执行)、T1547(启动或登录自动执行)、T1556 (修改认证流程) 🔄️等；
+ Privilege Escalation(TA0004)：T1055(进程注入, 包含DLL注入、PE注入、线程劫持、APC注入、TLS回调注入、进程镂空等)、T1134(令牌访问操作)、T1548(滥用权限提升控制)、T1611(逃逸到主机) 🔄️等；
+ Stealth(TA0005)：T1006(直接卷访问) 🔄️、T1014(RootKit) 🔄️、T1027(混淆文件或信息) 🔄️、T1036(伪装)、T1070(痕迹清除)、T1078 (有效账户) 🔄️、T1140(加密混淆文件或信息) 🔄️、T1205(流量信号) 🔄️、T1211(漏洞利用) 🔄️、T1218(System Binary Proxy Execution) 🔄️、T1220(XSL脚本处理) 🔄️、T1221(模板注入) 🔄️、T1497(虚拟化/沙箱规避) 🔄️、T1542(预启动) 🔄️、T1564(隐藏行为痕迹)、T1574(控制流劫持)、1620(反射加载)、T1622(调试器规避)等；
+ Defense Impairment(TA0112)：T1222(文件与目录权限修改)、T1553(破坏信任控制)、T1556(修改认证流程)、T1685(禁用安全工具)、T1686(禁用或修改系统防火墙)、T1687(漏洞利用) 🔄️等；
+ Credential Access(TA0006)：T1003(操作系统凭据转储)、T1056(输入捕获) 🔄️、T1110(暴力破解) 🔄️、T1552(不安全的凭据)、T1555(从密码存储中获取凭据)等；

---
${\color{red}请注意: 当前 WkDefender 正在进行大规模架构调整，存在大量流水线未接通的情况 !!!}$

如有兴趣或任何问题，可通过邮件与我交流（1578905282@qq.com），请说明来意，我会尽快回复。