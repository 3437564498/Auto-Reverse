# 实施状态与验收边界

更新：2026-10-15（Asia/Singapore）。设计基线为 [V1 主方案](android-arm64-so-cpp-recovery-V1.md)。`main` 已合并 PR #6（`1c2ef76`）；当前批次在 `codex/m1-integrated-project` 开发和验证。本页描述当前代码能力，推送、PR 与 Checks 状态以 [GitHub](https://github.com/3437564498/Auto-Reverse/pulls) 为准。

**完整 V1、M0-S、M0-R 和 M1 的完整退出条件尚未全部验收。** 本批将原有单候选验证扩展为可恢复的自动静态工程流水线，最高交付真实编译的局部 A1。用户暂时无法提供真实 DSH 模型环境，该项保留未验收；确定性静态生成、注入 Provider 和 SDK 离线预检均不计作真实模型验收。

## 当前新增能力

| 范围 | 已实现行为 | 保留边界 |
|---|---|---|
| 自动入口 | `recover-project` 串接清单、声明、源码提案、验证、选择、集成和最终报告；同输入与配置可按账本接续 | 确定性静态生成器，模型调用数 0；最多处理 64 个安全命名的普通导出函数 |
| 原库清单 | 保留原动态导出、导入、已发现定义函数和可执行区间字节；观察直接调用、SCC、全局量、TLS 和生命周期根 | 间接调用、未知范围、缺失函数和未闭合入口继续形成缺口；完整函数总数未知 |
| 标量契约 | 原 ELF 的 unsigned32/64 DWARF 声明核验；有界 bundle 原子冻结同一契约版本 | 仅有限声明形状，不等于完整类型推断、对象布局或原调用 ABI 证明 |
| 候选签名 | 由固定 Clang 实际 AST 与类型探针提取候选参数和返回类型，对比当前可信标量约束 | 歧义、扩展类型、未知属性与不支持声明不给匹配通过；候选自报类型无权威 |
| 受限源码生成 | 有类型整数叶函数生成，参数/返回宽度检查，UBFM/UBFX/UBFIZ 支持；固定生成源码另做安全审计 | 只覆盖受支持的 unsigned 叶函数语法；安全审计不证明任意 C++ 或全库无 UB |
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

本批增加实际 Clang 签名、类型约束 bundle、受控源码安全、多翻译单元链接、最终字节重证、原库清单、Android Profile、源码 ZIP/CMake 重建、持久宿主恢复及最终报告的正反样例与独立审查。自动样例含 unsigned32/64 函数及浮点、访存、全局量、初始化缺口，要求全输入分母与 UNKNOWN 不丢失。测试总数与最终验收快照在本批代码冻结后统一记录，不与旧批数字混用。

```bash
.venv/bin/python scripts/install_static_toolchains.py
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

本批将 [固定工具静态验收 workflow](../.github/workflows/static-acceptance.yml) 接入 PR 自动检查：当 `src/`、`tests/`、`scripts/`、`toolchains/`、`schemas/` 或该 workflow 变化时自动触发，用户无需手动 dispatch。该 job 下载并校验固定 NDK/Ghidra/JDK，安装 CMake 3.31.6，执行静态矩阵、证据契约样例、自动工程 ZIP 重建与新字节证明样例，再使用真实工具环境运行完整 Python 测试，并上传静态证据。workflow 配置已加入本批；远端是否实际成功须以 PR Checks 为准，不预先记作通过。

历史结果保持原文件：[候选验收](acceptance/2026-10-14-validation.json)、[修复与分支验收](acceptance/2026-10-14-feedback.json)、[证据与声明验收](acceptance/2026-10-14-evidence-contract.json)。这些结果对应各自冻结代码，不能直接作为本批新增模块已验收的结论。

## V1 尚未通过的范围

1. **M0-S 静态可信性完整退出条件**：现有整数/分支/受控内存与负向变异只覆盖明确模型；通用循环、复杂内存/别名、浮点、原子/屏障、PAC 等未闭合能力继续 UNKNOWN。
2. **完整类型与调用 ABI**：当前仅有限 unsigned 标量声明与签名核验；完整约束求解、聚合/向量返回、对象与字段布局、继承/虚表、this 调整、异常及完整原调用 ABI 尚未验收。
3. **整库工程和依赖闭包**：局部工程已能真实构建并打包；隐藏/内部函数、递归与互调、间接调用、外部效果、全局/TLS、初始化/析构及入口闭包尚未覆盖完整范围。不能靠缩小导出集合或复制原机器码宣称整库通过。
4. **完整 Android/JNI Profile**：重定位格式和 API 下界观察已实现；加载器语义、页大小/权限、运行库行为、JNI 普通/Fast/CriticalNative、动态注册与 DEX/Java 上下文仍需专项契约和负向样例。
5. **M0-R 与真实多 Agent 质量闭环**：缺少真实 DSH 模型环境，真实子会话恢复、截断、客户端重连、取消/清理与实际模型修复闭环未验收。账本 32 名额和注入 Provider 实验不是模型吞吐实验。
6. **M3 与发布门槛**：同输入/模型/质量规则下的真实 8/16/32 并发比较、Token/成本/延迟和完整质量门槛尚未测量；A2/A3 与发布选择未开放。M1 的零人工修改与可恢复部分链路已有实现，完整端到端退出条件仍未全部通过。

开发继续沿当前唯一活动分支推进；一批 PR 或 Checks 通过不表示完整 V1 收尾。未完工作集中跟踪 [总清单 #4](https://github.com/3437564498/Auto-Reverse/issues/4)，GitHub 操作见 [使用说明](github-usage.md)。
