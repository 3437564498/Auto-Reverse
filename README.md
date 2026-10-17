# Auto-Reverse

面向 Android `arm64-v8a` 共享库 `.so` 的全自动、纯静态 C++ 源码重建方案。采用版本化证据与 ABI 约束、有界多 Agent、小工作包、独立构建及静态语义验证；DeepSeek Harness（DSH）为客户端与 Agent Runtime，定制插件补齐业务能力。

不熟悉 GitHub 时，可先读 [GitHub 使用与交付](docs/github-usage.md)：平时查看 `main`，新更新集中在 [待审核更新](https://github.com/3437564498/Auto-Reverse/pulls)。正常只保留 `main` 和一个活动开发分支，同批修复更新同一个 PR；合并后的开发分支按审核提交自动清理。

当前主方案为 **1.0-design（V1）**，**完整 V1 尚未开发和验收完成**。本批接入可恢复的自动静态工程流水线：原库清单 → 有限标量声明冻结 → 候选签名与实际编译 → 最佳候选选择 → 多翻译单元链接 → 最终链接字节重新验证 → 源码工程 ZIP 与版本化报告。实际构建的支持子集最高为 **局部 A1**；原库所有已发现函数、导入、可执行字节和未恢复缺口继续保留，整库语义、完整调用 ABI 与入口闭包仍为 UNKNOWN。

流水线使用确定性静态生成器，模型调用数为零。DSH 账本、插件和 SDK 离线接线已实现；用户暂时无法提供真实 DSH 模型环境，该项保持未验收。当前进度与 V1 剩余范围见 [实施记录](docs/implementation-status.md)。

[PR #8](https://github.com/3437564498/Auto-Reverse/pull/8) 已合并到 `main`，原始布局声明事务的 GitHub 真实固定 NDK/Ghidra 完整回归为 **2187 passed、0 skipped、0 failed**。下一批把冻结布局约束接入实际候选、工程翻译单元及归档重建，集中在 [待审核更新](https://github.com/3437564498/Auto-Reverse/pulls)；布局声明本身等级保持 A0。各增量的来源、验收和限制见 [实施记录](docs/implementation-status.md)，当前远端 Checks 与可审核状态以活动 PR 为准。

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

`analyze` 输出 A0 静态体检报告。需要实际源码、编译产物与工程归档时，使用下面的 `recover-project`。`verify` 对明确函数范围内的真实 ARM64 字节进行比较，不执行输入或候选；未支持指令、未闭合路径和无法证明安全的访存给出 UNKNOWN。

```bash
.venv/bin/arm64-recover verify --original original.so --candidate candidate.so \
  --function add_seven --output comparison.json
.venv/bin/arm64-recover register-input ./libtarget.so
.venv/bin/arm64-recover register-policy policies/android-arm64-static.yaml
.venv/bin/arm64-recover worker
.venv/bin/arm64-recover mcp --transport stdio
```

MCP 使用登记后的 `input_ref`/`policy_ref`，短提交后由独立 worker 处理。stdio 和本地 Streamable HTTP 提供提交、查询、分页、取消和产物读取；目前为单用户本地服务，远端身份认证尚未接入。详细交付范围、实际验证和后续工包见 [实施记录](docs/implementation-status.md)。

自动工程流水线只运行分析器、编译器和 Solver；输入、候选库、模拟器和设备程序均不执行：

```bash
.venv/bin/python scripts/install_static_toolchains.py
export JAVA_HOME="$PWD/work/tools/jdk-21.0.8+9"
.venv/bin/python scripts/build_ndk_samples.py --output work/ndk-samples
.venv/bin/arm64-recover recover-project \
  --binary work/ndk-samples/original/libmicro.so --output work/recovered-project \
  --ndk-root work/tools/android-ndk-r27c --ghidra-home work/tools/ghidra_11.3.2_PUBLIC
cd integrations/dsh
npm run preflight
```

`--ghidra-home` 可选。输入上限为 256 MiB；本次自动生成最多处理 64 个安全命名的普通导出函数，其余范围保留为缺口。成功集成时，输出包含 `project.zip`、`candidate.so`、`report.json` 和 `status.json`；无法生成或构建时仍输出分类报告，不虚构工程。相同输入、工具和配置可重复执行同一命令接续；未确认清理的工具活动会保留占用并要求宿主对账。输出内的 `state/` 是私有账本，不应整体分享。详细命令、归档重建和中断处理见 [自动静态工程流水线](docs/static-project-pipeline.md)。

`preflight` 使用真实 DSH SDK 启停和有效配置核查，模型调用数为零；详情见 [DSH 接线与真实模型后续验收](integrations/dsh/README.md)。

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
.venv/bin/python scripts/run_project_pipeline_sample.py \
  --ndk-root work/tools/android-ndk-r27c --output work/project-pipeline-new
.venv/bin/python scripts/run_layout_dependency_sample.py \
  --ndk-root work/tools/android-ndk-r27c --output work/layout-dependency-new
```

候选回执只表示 RECORDED；可信后处理另行选择 `BEST_AVAILABLE`。最终报告可将真实编译的局部源码集合或局部工程记为 A1，并明确 `artifact_scope`；整库构建、ABI、语义、完整性仍分别保留 UNKNOWN。`FINAL`/`COMPLETED` 表示本次任务与资源已收尾，不表示完整 V1 或整库等价通过。宿主排队、反馈和公开读取见 [候选提交与持久独立验收](docs/candidate-validation.md)。

普通 CI 未安装 NDK/Ghidra 时明确 skip。相关源码、测试等变更的 PR 会自动触发 [固定工具静态验收](.github/workflows/static-acceptance.yml)：下载并校验固定 NDK/Ghidra/JDK，安装 CMake 3.31.6，运行完整 Python 测试、静态矩阵与源码 ZIP 重建/新字节验证样例，无需手动触发。是否实际通过以该 PR 的检查结果为准。

## 文档

| 文档 | 内容 |
|---|---|
| [V1 主方案](docs/android-arm64-so-cpp-recovery-V1.md) | 47 节统一需求、架构、DSH/插件、契约、实施与验收 |
| [DSH 专项调研](docs/main-child-agent-DSH-RESEARCH.md) | 固定源码能力、32 路联动配置、插件扩展和生命周期 |
| [证据与声明契约](docs/evidence-contracts.md) | 辅助交付消费、原始 DWARF 核验、版本冻结与当前限制 |
| [实际编译的布局依赖](docs/layout-dependencies.md) | 类型作用域、宿主编译期断言、跨 TU 一致性及源码归档重建 |
| [自动静态工程流水线](docs/static-project-pipeline.md) | 输入 `.so`、持久接续、多模块工程、最终字节验证与交付读取 |
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

更新日期：2026-10-16（Asia/Singapore）。
