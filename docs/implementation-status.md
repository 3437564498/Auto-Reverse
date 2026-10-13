# M0 实施与验收记录

更新：2026-10-14（Asia/Singapore）。设计基线：V1 `30c31f9`；首批原型提交：`2e2a23f`。历史草稿保持原文，实施事实在本页更新。

本轮已接通真实 Python–DSH 领域服务与静态工具链。**V1、M0-S 和 M0-R 的完整退出条件均尚未全部验收**。用户明确暂时无法提供 DSH 模型环境，因此没有运行真实模型或宣称模型恢复吞吐。

## 实际验收结果

| 检查 | 结果 | 范围 |
|---|---|---|
| Python 完整套件 | **683 passed** | 启用真实 NDK/Ghidra 集成；包括 300 个实际 SMT 非等价变异及独立审查回归 |
| TypeScript/Cordis | **28 passed** | 真实 Python RPC/SQLite/CAS、两独立进程共享配额、鉴权控制、官方工具 registry、实际 SDK 启停与有效 Profile |
| NDK r27c | PASS | ARM64/API21；shared/static libc++；C++17 helpers 和实际样本只编译链接 |
| Ghidra 11.3.2 | exported | 真实 ELF 静态导入、Raw P-code、原始地址/字节交叉核验、Java home 与进程组清理 |
| 受限恢复闭环 | 部分 A1 | NDK 原始微库 → Ghidra → C++ → NDK → 实际机器字节 SMT |
| SDK 离线预检 | PASS，模型调用数 **0** | 真实 `start/initialize/close`，native/spawn/32/maxTokensAsSuccess=false 有效值已观察 |

Python 有一条第三方 MCP settings forward-reference 警告，协议测试通过。注入 Activation Provider 的两个工作者只证明真实账本/CAS 集成；没有被当成真实模型子会话。

## 已实现的工作包

| 模块 | 当前能力 |
|---|---|
| `domain.py` / `backend_rpc.py` | SQLite Job/DAG/Attempt、租约/epoch、不可变回执/Outbox、真实共享 32 名额、取消/隔离、私有宿主 JSON-lines RPC |
| `artifacts.py` / `intake.py` | 输入登记、CAS 原子发布/hash 校验/分页、ELF64 LE AArch64 ET_DYN 有界体检、真实函数字节 |
| `integrations/dsh/` | 冻结 Task → 原子真实 Attempt、Python 子进程客户端、候选 staging/授权证据、单调 guard、BindingReady、鉴权 Unix socket、完整专用 Profile |
| `ghidra.py` / Java exporter | 固定 Headless 导入、结构化 `Instruction.getPcode()`、varnode 地址空间/位宽、控制流、原 opcode 能力校验和来源 hash |
| `build_gate.py` | 固定 NDK/Clang/参数、源码 include 与预处理限制、超时进程组清理、实际源码/helpers 编译与 ELF/export 结构检查 |
| `recovery.py` | 小型整数叶函数的确定性 C++ 生成、源映射、实际候选编译/重解码/SMT；原类型、原调用 ABI 和整库闭包仍 UNKNOWN |
| CLI/MCP/CI | 静态分析、工具链/受限恢复命令、输入/策略登记、私有 RPC、公开产物视图、Python/TS CI |

批次不再预生成 Attempt；只冻结任务，取得真实租约后才创建 Attempt。32 个实际账本名额由两个独立 Python 进程核验，第 33 个任务保持 READY，确认清理后才发放；这是设施容量实验，没有测量模型吞吐。

MCP 与私有 RPC 共用账本和候选别名解析。通过 RPC 提交的候选可由 MCP 列出/分页读取，质量保持 NOT_CHECKED。仅执行 intake 的轮询 worker 不会结束持有 DAG 工作包的 Job。

## 静态链路的实际边界

NDK 固定 **27.2.12479018/r27c**；Ghidra 固定 **11.3.2**；Temurin JDK 固定 **21.0.8+9**。公开下载 URL/SHA256 在 `toolchains/static.lock.json`，安装到 `work/tools/`。helper/Java exporter/pin 包含于 Python wheel，避免依赖开发 checkout 的资源路径。

`x+7` 对 `7+x` 的实际 ARM64 机器码在声明模型内为 EXACT_EQUIVALENT，`x+8` 为 DIFFERENT。真实 NDK 微库的恢复范围有 **8 个已发现函数、152 个可执行字节**，生成并验证 **1 个函数、8 字节**；**7 个函数和 144 字节**仍保留缺口。局部通过没有缩小全输入分母，也没有给出整库等级。

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
cd integrations/dsh
npm ci
npm test
npm run preflight
```

工具未安装时，对应真实集成测试明确 skip，skip 不算该项验收通过。恢复输出目录要求新建或为空，防止旧成功产物混入本次验证。

本地完整证据保存在 `work/root-final-recovery/`、`work/ndk-ghidra-original/`、`work/ndk-samples-r27c-api21-{shared,static}-o2/` 和 `work/static-samples/ghidra-boundaries/`。SDK preflight 的 private runtime 目录包含控制凭据，不纳入 Git；公开锁及文档只保存能力/版本事实。

## 独立审查修复

- CR/line-splice 可绕过 include 约束读取宿主头文件：已用实际 NDK 复现并修复。
- 共用 worker ID 阻断并发、工具早于真实 bind、root/尾审计错配、取消后的 failure 分类：已修复并回归。
- 同提案并发重放产生重复提交窗口：真实两个 RPC 进程只得到同回执、一次提交事件。
- 候选 alias 的 MCP 解析与旧 metadata 缺少 ref：服务共享 resolver，读取以数据库真实 ref 为准。
- 初版代码页符号内存误接受、RET 内跳截断、取消中新挂产物、分页循环：回归保留。

## 后续仍需完成

1. 有真实模型环境后，执行至少两个真实 Fresh DSH 工作者的成功、截断、工具限制、取消/重连及资源对账验收。脚本见 `integrations/dsh/README.md`；不得把注入 Provider 或离线启动当作模型通过。
2. M0-S 继续冻结整数/分支/受控内存正反样本矩阵、原始 ABI、完整性/路径与 UB 义务；当前微型函数链路不代表整个 M0-S 完成。
3. M1 全库函数/入口闭包、原类型/ABI 约束、Agent 候选的独立构建与修复反馈、批次恢复调度和当前质量聚合。
4. 后续类型/JNI/TLS/重定位、C++ 对象、异常/并发能力增量，以及实际 8/16/32 模型实验、生产 Temporal 和发布验收。

已完成设施与静态链路继续保留；V1 完成判断仍以各里程碑全部退出条件和固定样本验收为准。
