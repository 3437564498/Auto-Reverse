# Auto-Reverse

面向 Android `arm64-v8a` 共享库 `.so` 的全自动、纯静态 C++ 源码重建方案。采用版本化证据与 ABI 约束、有界多 Agent、小工作包、独立构建及静态语义验证；DeepSeek Harness（DSH）为客户端与 Agent Runtime，定制插件补齐业务能力。

不熟悉 GitHub 时，可先读 [GitHub 使用与交付](docs/github-usage.md)：平时查看 `main`，新更新集中在 [待审核更新](https://github.com/3437564498/Auto-Reverse/pulls)，正常只有一个活动 PR，无需切换多个开发分支。已合并旧分支已清理；自动清理流程进入 main 后，后续合并按审核提交清理开发分支。

当前主方案为 **1.0-design（V1）**。已接通 Python–DSH 账本/CAS、SDK 离线启动、Ghidra/NDK 静态恢复和持久独立验证；实际反例可生成有界修复工包，修复后保留当前最佳候选。补证据提案可独立消费，原 ELF 的有限 unsigned 标量 DWARF 声明可核验并冻结版本。整数叶恢复 v2 与 27 项真实静态矩阵已验证。完整类型/调用 ABI、候选签名匹配、整库工程集成和真实模型验收仍待完成；M0/M1 的完整退出条件尚未通过。

## 开发与运行

```bash
python -m venv .venv
.venv/bin/python -m pip install -r requirements.lock
.venv/bin/python -m pip install -e . --no-deps
.venv/bin/arm64-recover analyze --binary ./libtarget.so --output ./recovered
.venv/bin/pytest -q
cd integrations/dsh
npm ci
npm test
```

`analyze` 当前输出 A0 静态体检报告，构建、ABI 和语义状态分别保留。`verify` 对明确函数范围内的真实 ARM64 字节进行比较，不执行输入或候选；未支持指令、未闭合路径和无法证明安全的访存给出 UNKNOWN。

```bash
.venv/bin/arm64-recover verify --original original.so --candidate candidate.so \
  --function add_seven --output comparison.json
.venv/bin/arm64-recover register-input ./libtarget.so
.venv/bin/arm64-recover register-policy policies/android-arm64-static.yaml
.venv/bin/arm64-recover worker
.venv/bin/arm64-recover mcp --transport stdio
```

MCP 使用登记后的 `input_ref`/`policy_ref`，短提交后由独立 worker 处理。stdio 和本地 Streamable HTTP 提供提交、查询、分页、取消和产物读取；目前为单用户本地服务，远端身份认证尚未接入。详细交付范围、实际验证和后续工包见 [实施记录](docs/implementation-status.md)。

受限恢复链路只执行分析器、编译器和 Solver，不运行库：

```bash
.venv/bin/python scripts/install_static_toolchains.py
export JAVA_HOME="$PWD/work/tools/jdk-21.0.8+9"
.venv/bin/python scripts/build_ndk_samples.py --output work/ndk-samples
.venv/bin/arm64-recover recover-leaf \
  --binary work/ndk-samples/original/libmicro.so --output work/recovered-leaf \
  --ndk-root work/tools/android-ndk-r27c --ghidra-home work/tools/ghidra_11.3.2_PUBLIC
cd integrations/dsh
npm run preflight
```

恢复范围自动保留全部已发现符号和可执行字节分母；暂不支持的函数形成缺口。实际源码编译并核对产物指纹后最高交付 A1；局部机器验证不会提升为整库通过。`preflight` 使用真实 DSH SDK 启停和有效配置核查，模型调用数为零；详情见 [DSH 接线与真实模型后续验收](integrations/dsh/README.md)。

实际静态矩阵及无模型候选闭环可复现为：

```bash
.venv/bin/python scripts/run_static_acceptance.py \
  --ndk-root work/tools/android-ndk-r27c --ghidra-home work/tools/ghidra_11.3.2_PUBLIC \
  --output work/static-matrix-new
.venv/bin/python scripts/run_candidate_validation_sample.py \
  --ndk-root work/tools/android-ndk-r27c --output work/validation-sample-new
.venv/bin/python scripts/run_repair_loop_sample.py \
  --ndk-root work/tools/android-ndk-r27c --output work/repair-sample-new
.venv/bin/python scripts/run_evidence_contract_sample.py \
  --ndk-root work/tools/android-ndk-r27c --output work/evidence-contract-new
```

候选回执仍只表示 RECORDED。可信后处理可以选择局部 `BEST_AVAILABLE`，实际编译集合最高 A1；全库未集成时 Job 保持 A0，整体构建/ABI/语义/完整性 UNKNOWN。宿主排队、反馈和公开读取见 [候选提交与持久独立验收](docs/candidate-validation.md)。普通 CI 未安装 NDK/Ghidra 时明确 skip；手动静态验收 workflow 下载固定工具并上传实际证据。

## 文档

| 文档 | 内容 |
|---|---|
| [V1 主方案](docs/android-arm64-so-cpp-recovery-V1.md) | 47 节统一需求、架构、DSH/插件、契约、实施与验收 |
| [DSH 专项调研](docs/main-child-agent-DSH-RESEARCH.md) | 固定源码能力、32 路联动配置、插件扩展和生命周期 |
| [证据与声明契约](docs/evidence-contracts.md) | 辅助交付消费、原始 DWARF 核验、版本冻结与当前限制 |
| [已确认范围](docs/confirmed-scope.md) | 用户确认的目标、静态约束、多 Agent、32 路与插件方向 |
| [0.2 初稿快照](docs/snapshots/android-arm64-so-cpp-recovery-0.2-DRAFT-2026-10-13.md) | 本轮优化前的 66 节工作稿，原文保存 |
| [0.1 初始快照](docs/snapshots/android-arm64-so-cpp-recovery-INITIAL-2026-10-12.md) | 初始版本，用于追溯 |
| [DSH 初稿调研快照](docs/snapshots/main-child-agent-DSH-RESEARCH-INITIAL-2026-10-12.md) | V1 更新前的配套研究 |

## V1 设计基线

- 仅 Android ARM64；任务全自动；禁止运行目标、候选库、模拟器和设备程序。
- 部分混淆可处理；运行时解密/代码生成区域排除，缺口传播到入口闭包。
- 多 Agent、每个 Agent 少量任务：默认一个工作包、一个函数、一种候选方向，完成或上下文压力时轮换。
- 初始配置 32 路工作者，联动 Workflow/Subagent/PTC 与业务配额；Ghidra、构建、Solver 和模型请求独立背压。
- DSH 定制插件负责工包执行、证据读取、提案、策略、取消和审计，业务事实与验收由领域服务持有。
- Raw P-code 不自动代表完整机器语义；两侧按原始指令检查能力，C++ UB 保真、有限/条件/UNKNOWN 分别报告。
- 回执、Outbox、版本检查和历史轮换保障持久恢复；Job 结束与产物质量分开。

M0-S 静态语义与 M0-R DSH 受控运行两项原型的完整退出条件尚未全部通过；通过后重新冻结 MVP 子集、工期、成本和验收门槛。性能数字是待校准研发目标，不能解释为 Android `.so` 实测成功率。

更新日期：2026-10-14（Asia/Singapore）。
