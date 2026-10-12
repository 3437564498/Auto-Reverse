# Auto-Reverse

面向 Android `arm64-v8a` 共享库 `.so` 的全自动、纯静态 C++ 源码重建方案。设计采用持久任务调度、有边界的多 Agent 工作包、独立构建与静态语义验证，并预选 DeepSeek Harness（DSH）作为客户端和 Agent Runtime。

当前处于调研与方案设计阶段，主方案版本为 **0.2-draft**，尚未定稿为 V1，也尚未实现恢复系统或完成 DSH 联调。

## 文档

| 文档 | 内容 |
|---|---|
| [主方案初稿](docs/android-arm64-so-cpp-recovery-DRAFT.md) | 项目调研、架构、实施、验收，以及主／子会话和 DSH 增补，共 66 节 |
| [主／子会话与 DSH 调研](docs/main-child-agent-DSH-RESEARCH.md) | DSH 源码能力、生命周期限制、预选框架和相关文章 |
| [已确认设计范围](docs/confirmed-scope.md) | 用户已确认的目标、静态约束、加固范围和客户端要求 |
| [初始方案快照](docs/snapshots/android-arm64-so-cpp-recovery-INITIAL-2026-10-12.md) | 0.1-draft 历史版本，保留用于追溯；当前方案以主稿为准 |

## 已确认方向

- 仅 Android ARM64，不包含其他 Linux 目标或其他架构。
- 每个恢复任务全自动；分析和验收保持纯静态，禁止执行目标或候选库。
- 允许部分混淆，排除需要运行时解密或生成代码的区域。
- 质量优先，不通过省略必要证据减少 Token。
- 大阶段拆成有边界的 Agent 工作包，任务状态和验收结论由持久服务管理。
- 兼容官方 DSH，客户端 MCP 接入与后端 SDK 执行分别设计和验收。

## 文档维护

先确认大方向和初稿内容，再统一整合、校对任务与状态契约、调整实施及验收方案，形成 V1。当前性能门槛属于研发目标，不是已经测得的 Android `.so` 恢复成功率。

本次文档调研日期：2026-10-12。
