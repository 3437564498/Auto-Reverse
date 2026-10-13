# DSH 受控恢复插件原型

本目录已实现可构建的 TypeScript adapter、真实 Cordis entry 和静态工具策略。固定源码基线是 DeepSeek Harness `d743267388641bc76f17c45ce8b4c231aed1d32c`，官方公开包 `0.2.1-alpha.2`。当前验收级别为 **adapter-only**，**M0-R 尚未验收**：没有运行真实模型、SDK 后端进程或恢复目标库；没有修改用户 DSH 配置。

在仓库内运行：

```sh
cd integrations/dsh
npm ci --ignore-scripts
npm test
```

需要 Node >=22.19。`npm test` 先严格 TypeScript 编译，再运行 19 个测试。测试覆盖两个独立 worker 的注入 seam、Schema/截断、真实 Cordis 工具作用域与单调 guard、32+入队策略、startup/published 取消、迟到发布、清理失败占位及一个 Runtime 一个批次。32 名额测试使用明确的测试 Domain；不代表生产跨进程容量实测。

## 模块与实际 API

- `src/native-provider.ts` 使用官方 `ctx.subagents.startActivation`，保留 exact handle。显式传入 `outputSchema`、`maxDepth: 1`、`toolFilter`、`persona`、`agentOptions` 和 `delivery: 'caller'`；只允许本地 fresh spawn，能力不足拒绝，不退化到 SDK 子后端。
- DSH handle 只有 child Session ID，没有 activation ID。本插件在 `subagent/start` 读取实际 `runId`，按预留 Session ID 关联；在 `agent/created` 通过 exact live Agent 对象绑定 Attempt/角色。不会生成伪 activation ID。
- `src/plugin.ts` 是正式 Cordis 模块，导出 `name`、`inject`、`apply`。根的工具是 `run_recovery_batch(batch_ref)` / `get_recovery_batch()`；工作者只获得按真实绑定授权的分页 `evidence_read`、`contract_read`、`task_report` 和 DSH 自带的 `structured_output`。
- 根、子继承工具允许表为空；工作者工具在 worker **自身作用域** 注册，避免根的 restriction 将子需要的工具一起隐藏。全局 monotonic guard 同时拒绝未绑定/失效 Agent、Shell、再委托、自由 Workflow、动态插件与新增作用域越权工具。`structured_output` 只结束 Runtime 活动，不升级质量。
- `src/batch-runner.ts` 在第一个 await 前锁定单 Runtime 的 Job/批次。全局发放、持久队列及 fencing 交给领域客户端；满额返回 `QUEUED`，不无限重复创建。Batch ready 清单最多 64 个，实际运行总名额由 Domain 的共享 32 配额收口。
- 每项立即 `commitProposal`，不等待全部批次。只接收 `stopReason: completed` 且结构化提案完整的结果；`max-tokens`、缺失结构化结果、额外 quality 字段均拒绝。SDK 的 `finalResponse` 不用于产物归属。

## 与 Python 的共用契约

`src/proposal.ts` 在编译输出运行时直接读取根 `schemas/proposal.schema.json`、`schemas/work-package.schema.json`，AJV 验证完整业务契约。插件从共用 proposal Schema 自动投影 DSH 当前支持的 JSON Schema 子集，去掉其不支持的 `minLength` / `minimum` / `minItems`，这些限制保留在最终 AJV 验证。模型结果还必须显式给出所有字段，即使领域 Schema 为部分字段提供默认值。

提案仅包含 V1 的 PROPOSED 字段；`requested_followup_tasks` 是 JSON object 数组。输入快照、Task/Attempt、契约 revision 和 candidate namespace 从服务冻结绑定核对，不能用模型填对 ID 代替权限。Domain 仍须核验真实对象、hash、当前 epoch、租约和幂等事务。本包按 monorepo 路径使用共享 Schema；单独拷贝 `dist/` 不构成独立发布包。

## 必须提供的宿主服务

`inject` 要求真实 `recoveryDomain: DomainClient` 和 `recoveryHost: RecoveryHost` 服务；缺少服务时 Cordis 保持 PENDING。接口见 `src/contracts.ts`，没有进程内假全局队列。宿主必须提供：

1. `loadBatch` 冻结清单、`inspectProfile` 实际有效配置核查，不能把示例 YAML 当作运行时报告。
2. `tryAcquireWorker` 原子共享发放，满额保留持久排队；`bindActivation` 保存真实 Session / runId；版本检查与 `commitProposal` 持久回执。
3. `cancelJob` 幂等持久失效提案租约；工具资源清理确认、隔离、释放与审计。`readEvidence` 必须校验服务端 ref/分页/完整性及权限。
4. `authorizeRoot` 将真实根 Session 绑定一个已授权 Job/batch；`installControl` 建立独立、鉴权的控制端点。模型不能访问此通道或控制凭据。

**本轮未完成 Python DomainClient IPC 接线**。当前 TypeScript seam 的 BatchPlan 含预绑定 Attempt，而 Python DomainStore 在 lease 时创建 Attempt；后续接线应统一“冻结 Task 清单 → 原子发放返回 Attempt/lease”的语义，不应为满足接口而绕过实际领域发放。此接口存在是可测试扩展边界，不能据此宣称端到端已联通。

## 取消与资源归还

取消先在本地标记停止派发/提交，再等待 Domain 的持久 fencing，随后 abort startup 并精确 `dispose()` 已发布 handle。result/startup 等待使用 abort race；清理等待有期限。startup 忽略取消时会隔离其名额；迟到 handle 仍被精确 dispose。dispose 失败、超时或工具资源未确认停止时进入 QUARANTINED，拒绝 Runtime 复用，保留 Domain 容量。迟到清理不会自行解除隔离，需宿主资源对账确认。

`interrupt`、SDK 停止读取或用户客户端断开都不当作 Job 完整清理。若控制端点失败，宿主还需关闭独占 Job Runtime，并取得进程及工具资源退出确认；这部分运行时故障接线尚未验收。

## Profile 与验收边界

`examples/client-mcp.example.yml` 是用户客户端片段；`examples/worker-profile.example.yml` 是宿主 overlay 字段片段，不是已安装的完整 Profile。部署必须移除 Shell、自由执行、动态插件和非受控委托，并对最终启用插件/工具清单做实际预检。工作者使用 native 工具模式，SDK 服务 `maxTokensAsSuccess: false`，Subagent 原生容量显式 32。不能直接复用含 Shell 且无 Subagent 的 sdk-minimal Profile。

`examples/sdk-host.mjs` 按固定官方源码的真实 SDK API 展示宿主启动/关闭方式，需要单独安装同版本 SDK 包并实现上面两个宿主服务。该文件不是已经运行过的模型验证脚本。`compatibility-lock.json` 区分源码核查、公开包类型/工具测试和未运行的模型/部署项目。

M0-R 后续必须实际完成：领域服务/控制通道接线，完整 worker Profile 有效值证明，SDK Runtime 启动，两个真正 fresh 子会话，持久回执/重连，startup/published/commit 故障窗口与资源对账，再按 8/16/32 档压测。此原型不声称源码恢复、质量等价或 M0-R 已通过。
