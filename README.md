# Auto-Reverse

面向 Android `arm64-v8a` 共享库 `.so` 的全自动、纯静态 C++ 源码重建方案。采用版本化证据与 ABI 约束、有界多 Agent、小工作包、独立构建及静态语义验证；DeepSeek Harness（DSH）为客户端与 Agent Runtime，定制插件补齐业务能力。

当前主方案为 **1.0-design（V1）**。仓库已进入 **M0 原型开发**：提供可安装 Python 包、静态 ELF 体检、内容寻址证据、持久任务账本、CLI/MCP 和受限 ARM64 SMT 比较；DSH 定制插件使用固定官方包构建。完整 C++ 恢复系统、Ghidra/NDK 链路、真实模型联调和 32 路恢复吞吐仍待实现或验收。

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

## 文档

| 文档 | 内容 |
|---|---|
| [V1 主方案](docs/android-arm64-so-cpp-recovery-V1.md) | 47 节统一需求、架构、DSH/插件、契约、实施与验收 |
| [DSH 专项调研](docs/main-child-agent-DSH-RESEARCH.md) | 固定源码能力、32 路联动配置、插件扩展和生命周期 |
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

更新日期：2026-10-13（Asia/Singapore）。
