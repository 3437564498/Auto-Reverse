# 静态基础与持久候选验收记录

更新：2026-10-14（Asia/Singapore）。设计基线：V1 `30c31f9`；首批原型：`2e2a23f`；真实工具链：`0b40909`；独立候选验证：`4725297`（PR #3 已合并）。历史草稿保持原文，实施事实在本页更新。

本轮完成有界修复/补证据反馈计划、最佳候选/当前质量管理和单机后处理，真实反例 → repair 工包 → 修复候选 → NDK/SMT → 保留较好候选的设施闭环已跑通。GitHub 已清理全部已合并旧开发分支，并加入使用说明和合并后条件清理规则。**V1、M0-S、M0-R 和 M1 的完整退出条件均尚未全部验收**。用户明确暂时无法提供 DSH 模型环境，没有运行真实模型或宣称模型恢复吞吐。

## 实际验收结果

| 检查 | 结果 | 范围 |
|---|---|---|
| Python 完整套件 | **998 passed** | 最终冻结代码；启用真实 NDK/Ghidra 集成，无 skip；包括 300 个实际 SMT 非等价变异与独立审查 |
| TypeScript/Cordis | **28 passed** | 真实 Python RPC/SQLite/CAS、两独立进程共享配额、鉴权控制、官方工具 registry、实际 SDK 启停与有效 Profile |
| NDK r27c | PASS | ARM64/API21；shared/static libc++；C++17 helpers 和实际样本只编译链接 |
| Ghidra 11.3.2 | exported | 真实 ELF 静态导入、Raw P-code、原始地址/字节交叉核验、Java home 与进程组清理 |
| 受限恢复闭环 | 部分 A1 | NDK 原始微库 → Ghidra → C++ → NDK → 实际机器字节 SMT |
| 固定静态矩阵 | **27/27 匹配** | 6 EXACT、8 DIFFERENT、11 UNKNOWN、2 INVALID_PRECONDITION；两库真实 Ghidra 字节关联 |
| ELF ABI 结构 | **59 项测试通过** | 含真实 NDK 数据尺寸与动态版本样本；结构 PASS 不提升原调用 ABI |
| 持久候选活动 | 实际正反闭环通过 | 真实回执/CAS → NDK → ABI → SMT；幂等、重启读取、取消、隔离、当前版本校验 |
| 修复反馈与选择 | 实际三阶段样例通过 | DIFFERENT → 局部 EXACT → 晚 DIFFERENT；冻结反馈 batch 幂等，无提前 Attempt，保留较好候选 |
| 分支清理 | **13 项通过** | 含真实本地 Git 删除审核提交、并发新提交触发 lease 拒绝；自动流程进入 main 后生效 |
| SDK 离线预检 | PASS，模型调用数 **0** | 真实 `start/initialize/close`，native/spawn/32/maxTokensAsSuccess=false 有效值已观察 |

Python 有一条第三方 MCP settings forward-reference 警告，协议测试通过。注入 Activation Provider 的两个工作者只证明真实账本/CAS 集成；没有被当成真实模型子会话。

Ruff、全部 Schema 与 DSH 锁指纹、wheel 构建及打包资源检查通过。普通 GitHub CI 未配置 NDK/Ghidra 时明确 skip；固定工具矩阵另有手动 workflow 下载、校验 archive 并上传证据，本轮尚未宣称该新 workflow 已在远端触发。

## 已实现的工作包

| 模块 | 当前能力 |
|---|---|
| `domain.py` / `backend_rpc.py` | SQLite Job/DAG/Attempt、租约/epoch、不可变回执/Outbox、真实共享 32 名额、取消/隔离、私有宿主 JSON-lines RPC |
| `artifacts.py` / `intake.py` | 输入登记、CAS 原子发布/hash 校验/分页、ELF64 LE AArch64 ET_DYN 有界体检、真实函数字节 |
| `integrations/dsh/` | 冻结 Task → 原子真实 Attempt、Python 子进程客户端、候选 staging/授权证据、单调 guard、BindingReady、鉴权 Unix socket、完整专用 Profile |
| `ghidra.py` / Java exporter | 固定 Headless 导入、结构化 `Instruction.getPcode()`、varnode 地址空间/位宽、控制流、原 opcode 能力校验和来源 hash |
| `build_gate.py` | 固定 NDK/Clang/参数、源码 include 与预处理限制、超时进程组清理、实际源码/helpers 编译与 ELF/export 结构检查 |
| `abi.py` | 对照原/候选动态导出、SONAME/依赖、OBJECT/TLS 尺寸、st_other/variant PCS、版本与有界元数据；保留全原库分母 |
| `candidate_validation.py` | 冻结回执/源/输入/配置/所选工具 hash，SQLite 独立 claim、构建/ABI/局部语义、CAS 报告、事件/Outbox、隔离和清理后重排 |
| `repair_feedback.py` | 实际报告/proof/工具/epoch 校验，原子分类和冻结单函数 repair/evidence 计划；真实读取证据进展、预算/重复失败/更好候选停止 |
| `candidate_selection.py` | 当前 `BEST_AVAILABLE`、不可变快照/CAS/Outbox；变化立即撤销当前标记，保留原库符号与执行字节分母；无发布选择 |
| `postprocessing.py` | 可信宿主处理新报告版本、分类/选择/反馈、每批≤64 frozen Tasks与持久余量；不调用模型 |
| `recovery.py` v2 | unsigned 整数叶函数 C++ 生成、已初始化 x8..17 临时、逻辑/移位/MOVK、源映射与真实重编译/SMT；原类型/调用 ABI 仍 UNKNOWN |
| CLI/MCP/CI | 静态分析、工具链/受限恢复命令、输入/策略登记、私有 RPC、公开产物视图、Python/TS CI |

批次不再预生成 Attempt；只冻结任务，取得真实租约后才创建 Attempt。32 个实际账本名额由两个独立 Python 进程核验，第 33 个任务保持 READY，确认清理后才发放；这是设施容量实验，没有测量模型吞吐。

MCP 与私有 RPC 共用账本和候选别名解析。通过 RPC 提交的候选可由 MCP 列出/分页读取，质量保持 NOT_CHECKED。仅执行 intake 的轮询 worker 不会结束持有 DAG 工作包的 Job。

独立验证使用 `cpp_source` 四字段 envelope，当前实际回执/函数范围及 host 配置都由服务核对。两个独立宿主只能取得一个活动；已完成报告重启可读。运行中取消、旧 snapshot/epoch、同路径工具变化、旧 owner 或未确认清理均阻断当前成功发布。Job 取消/清理同时聚合 Agent 和验证工具资源，未完成验证阻止提前 COMPLETED。完整接口及当前边界见 [候选提交与持久独立验收](candidate-validation.md)。

反馈会累计真实 root 候选的 repair 预算，evidence 最多一次；只自报引用、局部页读取或循环读取自身诊断不算新增进展。成功页在真实 lease/Activation/manifest 授权事务内登记范围，完整覆盖才计交付。重复机器码/诊断、能力缺口、预算耗尽或同范围已有更好有效局部精确候选，均终止方向。补证据提案独立消费和类型/ABI 契约冻结仍未完成。

只选 `BEST_AVAILABLE`。局部 A1 编译集合不等于完整集成库，Job 保持 A0、整体 build/abi/semantic/completeness UNKNOWN；所选集合的 A1/PASS 另列范围。公开读取立即核验失效，不通过读接口修改 Job 或派发任务。实际选择清单保留 6 个已发现定义函数、另列 2 个导入函数及全部 152 可执行字节，当前只选 1 个定义函数/8 字节。恢复清单将定义/导入合计为8；两者都保留原始符号清单，完整函数总数与发现完整性仍未知。

## 静态链路的实际边界

NDK 固定 **27.2.12479018/r27c**；Ghidra 固定 **11.3.2**；Temurin JDK 固定 **21.0.8+9**。公开下载 URL/SHA256 在 `toolchains/static.lock.json`，安装到 `work/tools/`。helper/Java exporter/pin 包含于 Python wheel，避免依赖开发 checkout 的资源路径。

`x+7` 对 `7+x` 的实际 ARM64 机器码在声明模型内为 EXACT_EQUIVALENT，`x+8` 为 DIFFERENT。真实 NDK 微库的恢复范围有 **8 个已发现函数、152 个可执行字节**，生成并验证 **1 个函数、8 字节**；**7 个函数和 144 字节**仍保留缺口。局部通过没有缩小全输入分母，也没有给出整库等级。

另一个 v2 逻辑/临时/MOVK 微库实际完成 Ghidra → C++ → NDK → SMT：**1/8 函数、28/184 字节**恢复且局部 EXACT；**7 函数/156 字节**仍为缺口。真实编译器可能把合法 LSR 变成尚未支持的 UBFX，此时候选侧维持 UNKNOWN、solver 不运行。

独立活动的真实正反样本同样分别为局部 EXACT_EQUIVALENT / DIFFERENT；两份源码实际构建后可作为 A1 产物保存，但整体语义/调用 ABI 仍 UNKNOWN。候选提案/独立活动不自动升级质量；可信选择后仍仅局部集合 A1，Job 全库质量 UNKNOWN。完整 C++ UB、入口/全局闭包和实际集成工程仍待实现。

没有真实编译产物或 source/build/artifact 指纹不一致时，源码保留为未构建候选、等级 A0。实际编译后最高 A1；完整类型、原调用 ABI、初始化/全局量及入口闭包仍未知。

语义记录限制输入域、观察寄存器、内存与外部 RET 边界。初始 X30 明确排除两侧内部代码范围；实际 RET 可能回到代码内部则 UNKNOWN。代码/data alias、未知指令或未闭合路径不进入精确通过。始终 `whole_program_equivalence=false`。

真实 Ghidra 负面样本证实：LDXR 可被提升为普通 LOAD，DMB 产生 CALLOTHER，PACIASP 在固定语言下可产生空 Raw P-code；原始 opcode 能力检查仍令三者不获精确语义支持。Raw P-code 导出完整不代表函数发现或处理器模型完整。

## 可复现

```bash
.venv/bin/python scripts/install_static_toolchains.py
export JAVA_HOME="$PWD/work/tools/jdk-21.0.8+9"
.venv/bin/python scripts/build_ndk_samples.py --output work/ndk-samples
.venv/bin/arm64-recover recover-leaf \
  --binary work/ndk-samples/original/libmicro.so --output work/recovered-leaf \
  --ndk-root work/tools/android-ndk-r27c --ghidra-home work/tools/ghidra_11.3.2_PUBLIC
GHIDRA_HOME="$PWD/work/tools/ghidra_11.3.2_PUBLIC" .venv/bin/pytest -q
.venv/bin/python scripts/run_static_acceptance.py \
  --ndk-root work/tools/android-ndk-r27c --ghidra-home work/tools/ghidra_11.3.2_PUBLIC \
  --output work/static-matrix-new
.venv/bin/python scripts/run_candidate_validation_sample.py \
  --ndk-root work/tools/android-ndk-r27c --output work/validation-sample-new
.venv/bin/python scripts/run_repair_loop_sample.py \
  --ndk-root work/tools/android-ndk-r27c --output work/repair-sample-new
node --test .github/scripts/cleanup-merged-branch.test.cjs
cd integrations/dsh
npm ci
npm test
npm run preflight
```

工具未安装时，对应真实集成测试明确 skip，skip 不算该项验收通过。恢复输出目录要求新建或为空，防止旧成功产物混入本次验证。

本批最终证据保存在 `work/static-matrix-final-acceptance/`、`work/candidate-validation-final-acceptance/`、`work/leaf-v2-ghidra-mixed64/` 和 `work/validation-final-pytest.log`；可审阅摘要见 [本地验收记录](acceptance/2026-10-14-validation.json)。上一批证据仍在原 work 目录。SDK private runtime 含控制凭据，不纳入 Git；公开锁及文档只保存能力/版本事实。

本轮新增最终证据为 `work/repair-loop-final-acceptance/repair-loop-sample.json` 与 `work/feedback-final-pytest.log`，公开摘要见 [修复与分支验收](acceptance/2026-10-14-feedback.json)。GitHub 日常查看 [使用说明](github-usage.md) 和唯一活动 PR；V1 未完退出条件集中在 [总清单 #4](https://github.com/3437564498/Auto-Reverse/issues/4)。自动清理尚待本轮代码进入 main 后生效；已经合并的三条旧开发分支已由宿主核实 commit containment 和 SHA lease 后删除。

## 独立审查修复

- CR/line-splice 可绕过 include 约束读取宿主头文件：已用实际 NDK 复现并修复。
- 共用 worker ID 阻断并发、工具早于真实 bind、root/尾审计错配、取消后的 failure 分类：已修复并回归。
- 同提案并发重放产生重复提交窗口：真实两个 RPC 进程只得到同回执、一次提交事件。
- 候选 alias 的 MCP 解析与旧 metadata 缺少 ref：服务共享 resolver，读取以数据库真实 ref 为准。
- 初版代码页符号内存误接受、RET 内跳截断、取消中新挂产物、分页循环：回归保留。
- Job 取消漏统计独立验证工具、内部取消/完成守卫不完整：统一资源聚合和当前活动检查，独立审查回归覆盖。
- 发布事务前 config 变化、只回收 compiler parent 就释放工具资源：事务内重核验，观察进程组退出，未知清理保留隔离。
- 旧 compiler/helper/proof 指纹仍触发反馈：重核当前工具和证明，旧报告不得派新任务。
- READY反馈超过64使批次失败、同Activity重排新报告被旧决策压掉：分批保留余量，按(activity_id,report_ref)处理新版本。

## 后续仍需完成

1. 有真实模型环境后，执行至少两个真实 Fresh DSH 工作者的成功、截断、工具限制、取消/重连及资源对账验收。脚本见 `integrations/dsh/README.md`；不得把注入 Provider 或离线启动当作模型通过。
2. M0-S 已有固定 27 项矩阵，仍需扩大指令/ABI/完整性/UB 义务及独立 ISA 校验；该子集通过不代表整个 M0-S 完成。
3. M1 补证据交付独立消费/类型与 ABI 契约冻结、入口/全局闭包及完整工程集成、可信宿主工具恢复对账；当前确定性修复设施样例不代表真实模型无人值守全库恢复。
4. 后续类型/JNI/TLS/重定位、C++ 对象、异常/并发能力增量，以及实际 8/16/32 模型实验、生产 Temporal 和发布验收。

已完成设施与静态链路继续保留；V1 完成判断仍以各里程碑全部退出条件和固定样本验收为准。
