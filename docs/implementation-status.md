# 实施状态与验收边界

更新：2026-10-18（Asia/Singapore）。设计基线为 [V1 主方案](android-arm64-so-cpp-recovery-V1.md)。`main` 已合并 PR #12（`17d7b08`），ROR 独立 ISA 与实际 helper 验收已进入主分支。本批增加原始编码核验的 ANDS logical-immediate/TST 与局部前向 B.EQ/B.NE，集中在 [待审核更新](https://github.com/3437564498/Auto-Reverse/pulls) 的活动 PR。各验收数字对应下文明确的代码范围，当前 Checks 与可审核状态以活动 PR 页面为准。

**完整 V1、M0-S、M0-R 和 M1 的完整退出条件尚未全部验收。** 本批将原有单候选验证扩展为可恢复的自动静态工程流水线，最高交付真实编译的局部 A1。用户暂时无法提供真实 DSH 模型环境，该项保留未验收；确定性静态生成、注入 Provider 和 SDK 离线预检均不计作真实模型验收。

## 当前新增能力

| 范围 | 已实现行为 | 保留边界 |
|---|---|---|
| 自动入口 | `recover-project` 串接清单、声明、源码提案、验证、选择、集成和最终报告；同输入与配置可按账本接续 | 确定性静态生成器，模型调用数 0；最多处理 64 个安全命名的普通导出函数 |
| 原库清单 | 保留原动态导出、导入、已发现定义函数和可执行区间字节；观察直接调用、SCC、全局量、TLS 和生命周期根 | 间接调用、未知范围、缺失函数和未闭合入口继续形成缺口；完整函数总数未知 |
| 标量契约 | 原 ELF 的 unsigned32/64 DWARF 声明核验；有界 bundle 原子冻结同一契约版本 | 仅有限声明形状，不等于完整类型推断、对象布局或原调用 ABI 证明 |
| 原始结构布局证据 | `inspect-dwarf-layouts` 有界读取普通结构的 unsigned32/64 字段、嵌套结构声明范围与原始 DWARF 来源 | 只输出 A0 辅助声明；union、继承、位域、冲突与未知保留 UNKNOWN，完整类型系统未求解 |
| 候选结构布局核对 | `inspect-candidate-layouts` 使用实际固定 Clang AST 和宿主编译期断言核对普通/嵌套结构的字段类型、大小和偏移 | 声明匹配仍为 A0；原始缺失的对齐、完整调用 ABI、机器访存语义和通用类型约束求解继续未知 |
| 原始布局约束事务 | 有界原始物理类型目录、专用 `type_ids` 作用域、真实交付校验、多根及嵌套闭包一次冻结、current/history 与全局 revision 失效 | 仅原始存储声明 A0；完整类型系统和聚合调用 ABI 仍未知，宿主指定的有限候选依赖见下一行 |
| 实际 TU 布局依赖 | 指定物理类型闭包、宿主生成断言进入实际候选和工程编译、保守跨 TU C++ 类型核对、源码 ZIP 与 FINAL 绑定 | 有限 profile 已完成本地独立验收；函数仍限 unsigned32/64 标量，类型实际使用关系、聚合调用 ABI 与通用对象布局继续未知 |
| 候选签名 | 由固定 Clang 实际 AST 与类型探针提取候选参数和返回类型，对比当前可信标量约束 | 歧义、扩展类型、未知属性与不支持声明不给匹配通过；候选自报类型无权威 |
| 受限源码生成 | 旧有类型整数叶输出保持；新增 CMP/EQ-NE 选择及有限前向 B/CBZ/TBZ CFG，统一 carrier、路径汇合初始化/高位与 flags 检查 | 只覆盖 unsigned32/64 有界 profile；环、调用、内存恢复、其他 flags/条件与通用 C++ 继续未知 |
| 独立源码安全与 current | 独立解析源码 CFG/类型/初始化及原始高位可用性，重建实际 byte/span/CFG 绑定；工程与 FINAL 纯重验当前 staged source、契约、布局材料和实现 | 匹配 UNKNOWN 仍可局部 A1；审计不自动证明机器等价、原调用 ABI 或全库 UB，详见[无环恢复](acyclic-recovery.md) |
| 条件机器语义 | 原始编码 CMP、ANDS logical-immediate/TST、EQ/NE 选择及严格前向局部 B.cond；路径独立 NZCV、32/64 回绕与 W 零扩展 | LT/HI、BC、后向条件分支、寄存器 ANDS、其他 flags 更新仍 UNKNOWN；生成语法与调用 ABI 不扩大，详见[新 flags 边界](logical-flags.md) |
| 工程物化 | 当前所选源码分成独立翻译单元，生成受控公共声明，固定 NDK 真实编译与联合链接 | 不复制原机器码、不补空实现；缺少内部实现或声明冲突时保留失败/未知 |
| 最终产物验证 | 对最终联合 ELF 的实际字节逐个重新做局部 SMT，独立比较原库完整导出与依赖结构 | 不复用单候选证明替代最终证明；局部 EXACT 不提升为整库通过 |
| 源码工程归档 | 确定性 ZIP 包含实际源码、受控头文件、CMake 和公开报告；可用固定 NDK 重新编译 | ZIP 不包含原库、目标 `.so`、对象文件、私有账本或运行凭据；重建后须重新验证 |
| Android 静态 Profile | 有界解析 REL/RELA、标准与 Android 私有 RELR、APS2、TLS/生命周期及 JNI 线索；保留 API 下界 | 观察到标签不等于完整加载器兼容；JNI/DEX、TLS、重定位与初始化语义仍未闭合 |
| 工具持久化 | 候选验证、工程集成、Ghidra 分析独立活动；冻结输入、配置、工具与实现指纹 | 失联活动不自动重放；未确认的进程清理不归还占用 |
| 最终报告 | 将全输入分母、当前选择、实际工程、质量、资源清理与缺口冻结为版本化报告 | FINAL/COMPLETED 仅表示本次任务已收尾，允许合法 A0/局部 A1 与 UNKNOWN |

自动阶段顺序为 PLAN → TYPES → ANALYSIS（可选）→ RECOVER → INTEGRATE → FINAL。先冻结有限类型契约，再排队 Ghidra 分析，使分析活动与后续候选使用相同的当前 revision。

## 已有基础保持可用

SQLite/CAS 持有 Job、DAG、租约、Attempt、回执、Outbox、32 个共享 Agent 名额和取消账本。DSH 插件通过私有 Python RPC 使用实际账本；SDK 启停与有效 Profile 可离线核查。业务合同、构建参数、可信验证与发布选择由宿主持有，模型只能提交提案。

独立候选活动实际编译源码、比较 ELF 结构并验证函数机器字节。反例可形成有界修复工包，较差的后续候选不会覆盖已有较好候选；补证据提案单独消费，辅助发现不自动提升可信度。原始声明变化通过 revision/epoch 使旧来源失效，历史仍可追溯。

公共 CLI/MCP 可查询 Job、候选、集成和最终交付，支持有界分页与 Job 所有权校验。公共读接口不启动工具、不派发工作、不靠读取安装可选活动表；可信宿主排队、执行、冻结和对账另走管理入口。

## 怎样解释交付

| 字段或状态 | 含义 |
|---|---|
| `A0` | 只有分析/源码/缺口，或没有当前有效的实际编译产物 |
| `A1` | 当前有效的实际源码编译集合或局部工程；须同时查看 `artifact_scope` |
| `build.status=PASS` | 对应局部构建范围实际通过；`whole_library_build_status` 仍为 UNKNOWN |
| 局部 `EXACT_EQUIVALENT` | 最终产物中明确函数范围在声明机器模型和前提内等价 |
| 整体 ABI/语义/完整性 UNKNOWN | 原调用 ABI、入口与依赖闭包、未知代码或全库义务仍未解决 |
| `FINAL` / Job `COMPLETED` | DAG、活动和资源满足本次收尾条件；不是 V1 完成或可发布选择 |
| `INTERIM` | 还有未完成工作或未确认清理，不能结束 Job |
| `current_valid=false` | 当前输入、契约、工具、源码或证明绑定失效；历史报告仍可读取 |

始终保持 `whole_program_equivalence=false`、`original_calling_abi_verified=false`；不发布 A2/A3。源码安全审计的完整性只针对固定生成器产生的已核验叶函数，不推广为全库 C++ UB 证明。仅 ELF ABI 结构 PASS 也不能替代调用语义证明。

没有有效最终报告时，原始 Job 质量可能仍为 A0；最终报告能明确记录实际局部源码集合或局部工程 A1。报告视图在读取时重新核验输入、版本、工具、CAS、源码、构建与证明绑定；失效后当前质量降为 UNKNOWN，原质量另保留为历史。Job 已 COMPLETED 也不能绕过这些检查。

## 中断、取消与宿主对账

自动控制器持有每 Job 的排他锁，按持久阶段和游标推进。同输入、同工具和同配置重复执行，使用幂等键读取已提交结果；配置或实现指纹变化时拒绝静默续跑，需使用正确环境或新输出目录。

实际编译/Ghidra 子进程启动前保存启动意图，启动后绑定 owner、run、配置、PID、进程组、Linux boot ID 与进程起始时间。若宿主失联，`reconcile-host` 只隔离旧 owner；`confirm-host-cleanup` 独立观察已登记的整个进程组。租约过期、父进程退出、构造服务或重读报告都不等于确认清理。缺失进程登记、待定启动、身份不符和观察不完整时继续保留占用，不自动重放、不发布成功。

取消与完成守卫聚合 Agent、候选验证、工程集成和 Ghidra 活动。详细命令与输出目录规则见 [自动静态工程流水线](static-project-pipeline.md)。

## 验证与复现

固定工具为 NDK **r27c / 27.2.12479018**、Ghidra **11.3.2**、Temurin **21.0.8+9**，来源与 SHA256 见 `toolchains/static.lock.json`。所有样例只执行宿主基础设施；原库、候选库、模拟器和设备程序均不执行。

工程流水线基线在真实固定 NDK/Ghidra/JDK 下完整回归 **1964 passed、0 skipped、0 failed**（610.86 秒）。独立流水线故障审查 11 项通过；DSH 离线桥接 30 项和分支清理 13 项通过。Ruff、Schema 再生成和安装后 wheel 的模块、资源及流水线指纹检查通过。对应冻结代码及指纹见 [工程验收快照](acceptance/2026-10-15-integrated-project.json)。

随后推进的原始结构布局增量，独立解析测试 56 项、CLI 新增 3 项和既有接口 26 项的组合验收 **85 passed、0 skipped**；真实命令样例检查 10 个原始声明，6 个给出有限声明布局，另 4 个保留 UNKNOWN，全程为 A0。见 [布局证据验收](acceptance/2026-10-15-layout-evidence.json)。提交 `3a2f423` 的 [GitHub 固定工具完整验收](https://github.com/3437564498/Auto-Reverse/actions/runs/38725812676) 为 **2023 passed、0 skipped、0 failed**（712.70 秒）；该数字对应原始布局增量，后续候选布局检查另行验收。

候选结构布局增量已完成真实固定 NDK 的 **65 项新增测试**（44 项主测试、17 项独立对抗审查、4 项 CLI），与原始布局、签名和接口组合回归 **204 passed、0 skipped、0 failed**（26.58 秒）。独立审查发现并修复了命名空间被结构体作用域冒充、匿名结构体把额外成员隐藏在原始 padding 中的两处误判；零宽位域和匿名 union 反例也被拒绝。可复现样例实际完成 11 个场景：普通、嵌套、packed 和显式对齐 4 个有限声明匹配，错误类型/偏移/对齐/作用域与缺失原始证据等 7 个保留 FAIL/UNKNOWN。全部为 A0，缺失对齐继续未知。Ruff、Schema 再生成和独立安装的 wheel 模块、资源与 CLI 检查通过，详见 [候选布局验收](acceptance/2026-10-16-candidate-layout.json)。当前增量的完整 GitHub 验收以新提交的 Checks 为准。

提交 `22b3369` 的 [GitHub 固定工具完整验收](https://github.com/3437564498/Auto-Reverse/actions/runs/38780336239) 已通过 **2088 passed、0 skipped、0 failed**（669.74 秒），源码 ZIP 重建、11 场景布局核对和证据上传均通过。[普通 CI](https://github.com/3437564498/Auto-Reverse/actions/runs/38780336129) 为 1671 passed、417 项工具缺失明确 skip；DSH 离线 30 项和分支清理 13 项通过。这些数字属于候选布局检查提交，后续原始布局约束事务另行验收。

原始布局约束事务增量新增 **99 项测试**（26 项主测试、42 项独立对抗审查、26 项类型作用域/凭证、5 项接口），均已通过。固定工具相关回归分组完成 **553 passed**（80.66 秒）与自动流水线/独立故障审查 **24 passed**（297.01 秒），合计 577 项、0 skipped、0 failed。中断后缺少汇总的旧诊断日志未计作验收。真实离线样例以两个根冻结一个嵌套类型，版本只推进一次，实际宿主 CLI 重放无新增事件，current 重验有效、占用为 0；DSH 离线 30 项、分支清理 13 项、SDK 零模型预检、Ruff、Schema 与独立安装 wheel 检查通过。详见 [原始布局事务验收](acceptance/2026-10-16-layout-contracts.json)，本增量的完整远端结果以对应提交的 PR Checks 为准。

原始布局约束事务提交 `b2024d8` 的 [GitHub 固定工具完整验收](https://github.com/3437564498/Auto-Reverse/actions/runs/38853739218) 为 **2187 passed、0 skipped、0 failed**（645.68 秒），固定矩阵、源码 ZIP 新路径重建及新字节证明、候选布局和原始布局事务样例、证据上传全部通过。[普通 CI](https://github.com/3437564498/Auto-Reverse/actions/runs/38853739293) 为 1703 passed、484 项工具缺失明确 skip，DSH 离线 30 项与分支清理 13 项通过。PR #8 已合并；这些数字对应原始布局事务，不能作为后续实际 TU 依赖增量的验收。

实际 TU 布局依赖增量新增 **137 项测试**：23 项核心、15 项候选链、62 项独立对抗、9 项反馈、10 项接口及 18 项工程/归档/FINAL。核心相关 597 项和既有 service/FINAL 67 项通过；归档最后修复后，18 项工程、62 项独审及 137 项构建/归档重新通过。合计唯一相关用例 682 项，新增 137 项已包含其中，复验不重复累加。原文/guarded source 混淆、源码角色越权、物理 ID 重标绕过、打包丢依赖、强制头宏抹除断言及 include 影子文件均有实测反例并修复。无补丁 CLI 样例完成 1 根加 1 派生类型、两个实际候选/工程 TU、ZIP 新路径 CMake 重建与两个新链接函数重新 EXACT、FINAL current 有效且占用 0；原库 7 个已发现函数和 160 字节分母保留。39 模块/3 资源/9 Schema 的独立安装 wheel、Ruff、Schema、离线 DSH 30 项、分支清理 13 项和零模型 SDK 预检通过。详见[本批验收快照](acceptance/2026-10-16-layout-dependencies.json)与[使用边界](layout-dependencies.md)。该提交 `4f43eb6` 的[固定工具 CI](https://github.com/3437564498/Auto-Reverse/actions/runs/39000590490) 实际为 **2322 passed、2 skipped、0 failed**（888.81 秒）；两项 skip 是归档反例测试未定位到 pip 安装的 CMake，不能记作远端已执行。全部真实样例和证据上传通过，普通 CI 为 1713 passed、611 项工具缺失 skip。下一条件模型批次显式传入 CI 的实际 CMake 路径，补齐这两项执行。

有限条件机器模型新增 **210 项测试**（83 项实现、71 项独立机器语义对抗、36 项真实编译、20 项证明绑定），分别通过。真实固定 NDK 重编 20 个 ELF，正例、反转条件和常量变异、32/64 位回绕、LT/O0 与原有观察边界符合预期；缺工具的独立 skip 分支不计作真实编译验收。固定 NDK/Ghidra 静态矩阵扩展到 36 个场景并全部符合预期，其中新增 5 个局部 EXACT、2 个 DIFFERENT、2 个 UNKNOWN。实际布局/候选选择/两 TU 工程/ZIP 新路径重建与新字节两个 EXACT、FINAL current 和资源归零在新模型及严格 JSON 读取器下重新通过。独立安装包核对 39 模块、3 资源、9 Schema，并从安装包静态证明 CMP/CSEL 与 CBZ 参考等价；Ruff、Schema、DSH 离线 30 和分支守卫 13 项通过。边界详见[条件机器模型](machine-conditions.md)。

本地全量遍历为 **2530 passed、2 failed、2 skipped**（709.23 秒，1 条既有警告）：两处失败均为旧静态矩阵断言仍固定 27 场景，已更新为 36 并增加新条件分类检查，整个矩阵测试文件 **14 passed**（24.91 秒）；两处 skip 因隔离树旧测试只识别仓库内工具路径，配置路径后两项真实 NDK/CMake/ZIP 测试 **2 passed**（18.46 秒）。生产模块在遍历与补验期间未改，最终去重覆盖 2534 个用例，新增 210 项已包含，补验中的重复用例不累加；初次失败和 skip 原样保留在[冻结快照](acceptance/2026-10-17-eqne-machine-model.json)。本提交仍需等待新的 GitHub 完整 CI，不用分组结果冒充一次无失败全量运行。

条件机器模型提交 `6216d0c` 的[固定工具完整 CI](https://github.com/3437564498/Auto-Reverse/actions/runs/39002389361) 已实际通过 **2534 passed、0 skipped、0 failed**（933.12 秒，1 条既有警告），36 场景及全部真实样例、证据上传成功；前批 CMake skip 本轮已执行。普通 CI 为 1887 passed、647 个工具缺失 skip，DSH 离线 30 和分支守卫 13 项通过。PR #10 已合并，完整 V1 仍未完成。

有限无环条件恢复批次新增 **355 项测试**，分别通过：61 恢复核心、49 独立源码 checker、170 raw/source/map 攻击、41 真实编译、20 工程/current/FINAL 和 14 无形状契约的独立工程攻击。生产源码冻结后的本地固定 NDK/Ghidra/JDK/CMake 完整回归为 **2889 passed、0 skipped、0 failed**（854.09 秒，1 条既有警告），新增 355 项已包含其中。独立编译实际产生 38 个新 ELF，六个自然 O2 和七个独立 raw CFG 完成恢复/安全审计/签名/新字节 EXACT，实际条件及常量变异得到 DIFFERENT；LT/TST/O0 等仍 UNKNOWN。条件源码携带布局 guard 的两 TU 工程及 ZIP 新路径重建、新字节证明、当前源码审计、FINAL 和资源归零通过，自动控制器恢复及禁工具续跑通过。独立安装 wheel 的 41 模块、3 资源和 9 Schema 字节一致；聚合 `recover-leaf` 的实际编译与映射跨度、DSH 离线 30 项和分支清理 13 项通过。实际输入、实现指纹与分母见[本批冻结验收](acceptance/2026-10-18-acyclic-recovery.json)。这些是该冻结提交的本地实际结果，其远端验收见下文 PR #11 的最终结果。

PR #11 的冻结实现提交 `0a1bdc9` 已在 [GitHub 固定工具完整 CI](https://github.com/3437564498/Auto-Reverse/actions/runs/39051357897) 实际通过 **2889 passed、0 skipped、0 failed**（1040.63 秒，1 条既有警告）；36 场景矩阵、全部工程/布局/条件 guarded TU、ZIP 新路径重建及新字节证明与[证据上传](https://github.com/3437564498/Auto-Reverse/actions/runs/39051357897/artifacts/12108296050)均通过。[普通 CI](https://github.com/3437564498/Auto-Reverse/actions/runs/39051357911) 为 2164 passed、725 项工具缺失 skip（107.85 秒），Ruff/Schema、DSH 离线 30 与分支守卫 13 项通过。PR 已合并 `ed46fc0`，旧开发分支已清理；冻结快照中的远端 pending 表示提交时状态，最终远端结果以这里关联的同一提交日志为准。

本批 ROR 验收新增 **409 项测试**（334 独立 ISA、74 实际 helper 编译、1 矩阵分类守卫），本地分组实际通过独立 ISA 334 项、真实编译 74 项与矩阵 15 项，去重共 **423 passed、0 skipped、0 failed**；其中包括既有矩阵测试，数字不重复累加。真实固定 NDK/Ghidra CLI 完整矩阵 **48/48** 符合预期，新增 12 个 ROR 场景为 6 EXACT、3 DIFFERENT、3 UNKNOWN。实际 packaged helper 生成 **42 份新 ELF**，70 个完整机器比较为 **26 EXACT、21 DIFFERENT、23 UNKNOWN**；另 4 份任意 helper 源码安全审计保留 UNKNOWN。64 位变量 helper 的实际 ANDS/B.EQ 编译形态超出 profile（22 个机器 UNKNOWN），另 1 个 UNKNOWN 来自缺失内存区域契约；不扩展生产语义或修改头文件来迫使通过。uint32 零旋转身份 RET 的两份高半反例保留，显式 write_w 的 uint64 返回另行验证。126 次工具命令均确认清理，41 生产模块与 3 资源字节和 main 完全一致。独立审查的 994 个非空域 UNSAT 与 94 个不可行分区分列，不加入 pytest 数量。详见 [ROR 边界](ror-acceptance.md)及[冻结验收](acceptance/2026-10-18-ror-independent.json)。该冻结提交随后已通过 [PR #12 固定工具完整远端 CI](https://github.com/3437564498/Auto-Reverse/actions/runs/39104858560)：**3298 passed、0 skipped、0 failed**（1091.11 秒，1 条既有警告），48 场景矩阵、全部工程/布局/条件/ZIP 样例及[证据上传](https://github.com/3437564498/Auto-Reverse/actions/runs/39104858560/artifacts/12128098943)通过。[普通 CI](https://github.com/3437564498/Auto-Reverse/actions/runs/39104858429) 为 2499 passed、799 项工具缺失 skip（81.59 秒），Ruff/Schema、DSH 离线 30 和分支守卫 13 项通过。这些结果验收 `36c8da7`，不替代后续 ANDS 模型增量的完整验收。

真实 CLI 样例保留 5 个原始导出、11 个已发现函数范围和 216 字节可执行分母，恢复并集成 2 个 unsigned32/64 函数；浮点、访存、全局量、初始化继续形成缺口。Ghidra 导出 54 条指令并独立核对原始字节，同目录恢复无新增任务、事件或工具活动，所有资源清理确认。源码 ZIP 解包后 CMake 重建，再对新构建绑定下的 2 个函数重新证明 EXACT，未复用历史证明。详细记录见 [工程流水线样例](acceptance/2026-10-15-project-pipeline.json)。

```bash
.venv/bin/python scripts/install_static_toolchains.py
.venv/bin/python -m pip install cmake==3.31.6
export JAVA_HOME="$PWD/work/tools/jdk-21.0.8+9"
export GHIDRA_HOME="$PWD/work/tools/ghidra_11.3.2_PUBLIC"
export AUTO_REVERSE_TEST_NDK_ROOT="$PWD/work/tools/android-ndk-r27c"
.venv/bin/pytest -q
.venv/bin/python scripts/run_project_pipeline_sample.py \
  --ndk-root work/tools/android-ndk-r27c --output work/project-pipeline-new
.venv/bin/python scripts/run_static_acceptance.py \
  --ndk-root work/tools/android-ndk-r27c --ghidra-home work/tools/ghidra_11.3.2_PUBLIC \
  --output work/static-matrix-new
node --test .github/scripts/cleanup-merged-branch.test.cjs
cd integrations/dsh
npm ci
npm test
npm run preflight
```

`run_project_pipeline_sample.py` 会生成真实 NDK 原库，调用自动流水线，解包源码 ZIP，用 CMake 再构建并对新产物重新做静态证明。重新构建不继承旧报告的当前权威。工具未配置时对应测试明确 skip；普通 GitHub CI 的工具缺失 skip 不能代替真实 NDK/Ghidra 验收。SDK 预检的模型调用数仍为 0。

本批将 [固定工具静态验收 workflow](../.github/workflows/static-acceptance.yml) 接入 PR 自动检查：当 `src/`、`tests/`、`scripts/`、`toolchains/`、`schemas/` 或该 workflow 变化时自动触发，用户无需手动 dispatch。该 job 下载并校验固定 NDK/Ghidra/JDK，安装 CMake 3.31.6，执行静态矩阵、证据契约样例、自动工程 ZIP 重建与新字节证明样例、11 场景候选结构布局、原始布局事务，以及实际布局依赖的两 TU/ZIP/新字节证明样例，再使用真实工具环境运行完整 Python 测试，并上传静态证据。远端是否实际成功须以当前提交的 PR Checks 为准，不预先记作通过。

历史结果保持原文件：[候选验收](acceptance/2026-10-14-validation.json)、[修复与分支验收](acceptance/2026-10-14-feedback.json)、[证据与声明验收](acceptance/2026-10-14-evidence-contract.json)。这些结果对应各自冻结代码，不能直接作为本批新增模块已验收的结论。

当前本地模型增量限定 ANDS logical-immediate/TST 与严格前向局部 B.EQ/B.NE。实现 48 项、独立对抗 190 项、实际编译 97 项、proof/current 22 项及兼容编译 41 项均已实际通过；实际编译 55 份新 ELF，83 个比较为 44 EXACT、37 DIFFERENT、2 UNKNOWN，另 10 raw 边界及 4 源码安全审计 UNKNOWN。高地址 Capstone signed 目标导致的误拒已修复。初轮完整回归的旧 TST 未知断言失败后中断（1 failed、347 passed、78.06 秒），已保留并补独立 TBZ/ADD/SUB 参考；完整源码生成边界未扩大。固定 NDK/Ghidra 矩阵为 60/60，独立安装 wheel 的 41 模块/3 资源/9 Schema 与新 helper 机器证明通过，DSH 离线 30 与分支守卫 13 项通过。冻结源码后的固定 NDK/Ghidra/JDK/CMake 完整本地回归实际为 **3582 passed、0 skipped、0 failed**（869.36 秒，1 条既有警告），新增 **284 项**已包含其中（48 实现、190 独审、23 编译、22 证明/current、1 矩阵守卫）。最初失败过程与最终输入、实现和工具绑定见[本批冻结验收](acceptance/2026-10-18-logical-flags.json)。本批新的远端完整结果仍须核对当前提交的实际日志，不以本地或旧 PR 代替。

## V1 尚未通过的范围

1. **M0-S 静态可信性完整退出条件**：现有整数/分支/受控内存与负向变异只覆盖明确模型；通用循环、复杂内存/别名、浮点、原子/屏障、PAC 等未闭合能力继续 UNKNOWN。
2. **完整类型与调用 ABI**：当前有有限 unsigned 标量契约、候选签名核验、普通结构的 A0 布局证据、有限候选声明核对及原始布局声明事务；通用类型依赖推断、约束求解、聚合/向量返回和任意全工程对象布局一致性、继承/虚表、this 调整、异常及完整原调用 ABI 尚未验收。
3. **整库工程和依赖闭包**：局部工程已能真实构建并打包；隐藏/内部函数、递归与互调、间接调用、外部效果、全局/TLS、初始化/析构及入口闭包尚未覆盖完整范围。不能靠缩小导出集合或复制原机器码宣称整库通过。
4. **完整 Android/JNI Profile**：重定位格式和 API 下界观察已实现；加载器语义、页大小/权限、运行库行为、JNI 普通/Fast/CriticalNative、动态注册与 DEX/Java 上下文仍需专项契约和负向样例。
5. **M0-R 与真实多 Agent 质量闭环**：缺少真实 DSH 模型环境，真实子会话恢复、截断、客户端重连、取消/清理与实际模型修复闭环未验收。账本 32 名额和注入 Provider 实验不是模型吞吐实验。
6. **M3 与发布门槛**：同输入/模型/质量规则下的真实 8/16/32 并发比较、Token/成本/延迟和完整质量门槛尚未测量；A2/A3 与发布选择未开放。M1 的零人工修改与可恢复部分链路已有实现，完整端到端退出条件仍未全部通过。

开发继续沿当前唯一活动分支推进；一批 PR 或 Checks 通过不表示完整 V1 收尾。未完工作集中跟踪 [总清单 #4](https://github.com/3437564498/Auto-Reverse/issues/4)，GitHub 操作见 [使用说明](github-usage.md)。
