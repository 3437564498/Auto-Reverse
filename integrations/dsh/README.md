# DSH 受控恢复接线

固定官方源码基线 `d743267388641bc76f17c45ce8b4c231aed1d32c`，公开包 `0.2.1-alpha.2`。本目录已接入**真实 Python 子进程 JSON-lines RPC、SQLite 账本及不可变 CAS**，并实际启动/关闭专用 Cordis Profile 的 SDK Runtime，完成离线有效配置预检。**没有调用模型，M0-R 尚未验收**。两个 activation 的提案集成测试使用明确的注入 Provider；目标库和候选库均未执行，用户 DSH 配置未修改。

```sh
# 仓库根先安装 Python 项目与 requirements.lock，或准备 .venv。
cd integrations/dsh
npm ci --ignore-scripts
npm test
npm run preflight
```

Node >=22.19。`npm test` 严格编译并运行 30 项测试，包括真实 Python RPC/SQLite/CAS、辅助 JSON 交付与官方工具 registry 隔离，以及 SDK/有效 Profile 检查；基础生命周期/工具作用域测试保留。CI 可设置 `AUTO_REVERSE_PYTHON` 为 Python 可执行文件路径。SDK 离线测试只执行 `start` / `initialize` / `close`，不创建模型请求。

## 冻结任务、真实 Attempt 与提案

`BatchPlan` 只包含 `{batch_ref, job_id, tasks: WorkPackageSpec[]}`。旧 `attempts` 清单和提前生成的 `attempt_id` 被拒绝。`task.lease` 在真实账本事务中创建 Attempt，并返回 `{binding:{work,epoch,execution_key},lease:{token}}`；发放后的 work 包含真实 attempt_id，namespace 为 `candidate://job/task/attempt`。BatchRunner 从此仅使用该 binding，并核对它与冻结 Task 的身份/范围/版本/权限。

`src/python-domain-client.ts` 固定启动：

```text
python -m auto_reverse.cli --state-dir <state> domain-rpc
```

无 Shell 和任意命令参数。stdin/stdout 为独占管道，按 request id 关联 JSON-lines 回应；stderr 私下排空，异常只暴露稳定错误码。lease/token 不进入提示词、工具参数、结果或日志。每个任务拥有独立 worker identity，两个/32 个任务不会因复用 worker_id 被账本当作同一工人。

工作者 `candidate_stage(name, content)` 只接收有界 JSON object 文本及简单文件名，经 `artifact.stage` 写入真实 CAS、创建不可变 candidate alias，返回 artifact_ref/hash/size。提案必须使用实际返回的 refs；服务拒绝不存在、越权或 hash 不符的对象。完整共用 Schema、版本/身份、lease/epoch、Activation 和幂等事务仍由服务核对；提案只能是 `PROPOSED`，无法设置 semantic quality。`finalResponse` 不作为提案证据。

提交给独立构建活动的 C++ 候选使用四字段 envelope：`{schema_version:1,kind:"cpp_source",symbol,source}`，完整 Schema 由 `contract_read.source_candidate_contract` 提供。后端核对实际回执、冻结函数范围和配置后独立 NDK 编译、ABI 结构检查和机器比较；额外 flags/quality/路径不会成为编译参数。该活动不会阻塞工作子会话，也不自动提升 Job quality。后续宿主及 MCP 读取接口见 [持久候选验收](../../docs/candidate-validation.md)。

`type_abi` / `evidence` 工作者同样使用已有 `candidate_stage` / Proposal 接口。函数类型包提交 `scalar_abi_constraints` / `scalar_abi_bundle`；带专用 `scope.type_ids` 的布局包提交 `original_layout_bundle`，不能将类型名塞进函数作用域。证据角色提交 `scoped_evidence` / `evidence_gap`。Schema 与当前声明约束通过 `contract_read` 提供。工包须明确授予 `candidate_submit`；`constraint_submit` 尚不具备独立暂存通路。可信宿主独立消费和冻结，工作者没有冻结权限。空类型作用域省略以兼容旧任务。真实模型仍未调用；边界见 [证据与声明契约](../../docs/evidence-contracts.md)。

工具若早于 `startActivation` 返回便开始执行，会等待 `attempt.bind` 真实 RPC 成功后再发送领域请求。该等待有超时和 AbortSignal，绑定失败不会绕过权限。真实 RPC 回归覆盖此时序，没有通过人工 scheduler tick 避开它。

## Cordis 及宿主控制

- `src/plugin.ts` 提供根的 `run_recovery_batch` / `get_recovery_batch`；子只获得按冻结权限注册的 `evidence_read`、`contract_read`、`task_report`、`candidate_stage` 及 DSH 的 `structured_output`。
- `src/native-provider.ts` 使用官方 `ctx.subagents.startActivation`，通过真实 `subagent/start.runId` 和 exact live Agent 关联 Activation。仅接受本地 fresh spawn，并显式使用 native 工具、结构化 schema、depth=1、空继承工具允许表。
- 全局单调 guard 拒绝 Shell、再委托、Workflow、动态插件及新增作用域越权工具。scope-local 注册不能绕过 guard，candidate_stage/structured_output 均需要 `candidate_submit`。
- `src/host-plugin.ts` 是可加载 Cordis 服务插件，注入 `recoveryDomain` 和 `recoveryHost`；`src/host.ts` 建立只供宿主使用的 Unix socket。父目录要求本用户拥有且 0700，socket/token 文件为 0600，token 至少32字节，每个请求恒时鉴权。控制协议支持 `authorize_root`、`cancel`、`preflight` 和精简 `receipts`；根授权必须与真实 batch/job 匹配，不能任意重新绑定已有根。
- 根工具与 worker 工具均写真实领域审计。服务校验根 batch/job、worker token/exact session；合法收尾审计不会重新授权已隔离/已清理的 Attempt。

`src/profile.ts` 检查实际 `ctx.subagents` 的 spawn 能力、真实容量配置、`ctx.tools` 的 native mode，以及 ACTIVE SDK server fiber 的有效 `maxTokensAsSuccess=false`；Python `domain.inspect` 观察真实共享配额32和 static-only 协议。未观察到的值记录 `missingPreflight` 并拒绝运行，示例 YAML 不当作核查证明。公开包版本与源码兼容基线有锁定；npm 工件和源码 commit 的独立 provenance 仍未证明。

## 取消、超时与配额

全局 32 个名额、排队和 fencing 均由 SQLite 事务决定。两个独立 Python RPC 进程真实竞争32名额，第33任务保留 READY，确认 cleanup 后才可发放。一个 Runtime 在首次 await 前锁定一个批次。

Job 取消先阻止本地提交，再持久失效所有 lease，随后 abort startup、精确 dispose 已发布 handle。只有真实 dispose 成功且本宿主工具 RPC 已清空才提交 `attempt.cleanup{confirmed:true}`。startup/dispose/工具清理未确认会隔离并保持容量；迟到 handle 仍 dispose，不自动归还隔离名额。

读 RPC 超时/abort 会停止并确认原 Python 进程退出，在独立新管道执行 `worker.fence`，覆盖包括尚未回包的 lease 在内的全部 owned worker identities；client 永久拒绝再次发放/提交。真实 SQLite 锁阻塞读的集成测试确认 abort 后无法提交且名额不被当作已清理。取消窗口不重复写失败记录，以免已失效 Attempt 的合法取消被 STALE_LEASE 误判。

## 完整专用 Profile 与后续真实模型验收

`examples/dedicated-profile.mjs` 物化完整 Profile，bundle list 为空，不继承 sdk-minimal。树包含 SDK server、Agent/Session、native tools、fresh spawn、持久 session 与真实 Python/control 宿主；没有 Shell、Workflow、PTC 工具或动态插件。`examples/worker-profile.example.yml` 仅保留为字段参考。

离线预检可显式指定路径：

```sh
node examples/sdk-host.mjs --repository /absolute/Auto-Reverse \
  --python /absolute/Auto-Reverse/.venv/bin/python \
  --state-dir /absolute/Auto-Reverse/work/dsh-domain \
  --runtime-dir /absolute/Auto-Reverse/work/dsh-runtime-new
```

脚本在新 runtime-dir 下生成独立 DSH home/token/Profile，写 `preflight.json`，实际 SDK `start()` / `close()`；报告 `model_calls:0`、`m0_r_accepted:false`。无需模型凭据，也不使用 fake model。

后续有实际模型环境时，先在该 state-dir 通过可信 host RPC 创建 Job、证据 manifest、至少两项 READY frozen tasks 及 batch，再运行：

```sh
# 由宿主私下提供 DEEPSEEK_API_KEY，不把密钥写进命令或 Profile。
node examples/sdk-host.mjs --real-model \
  --state-dir /absolute/state --runtime-dir /absolute/new-private-runtime \
  --job-id <existing-job-id> --batch-ref <existing-batch-ref>
```

该模式启用真实模型 Provider、鉴权授权新 Root Session，再让根调用批次工具。`model-run-proof.json` 收集不同 child Session 和真实领域 receipts；少于两个持久 RECORDED 提案会失败。脚本仍不自动宣布 M0-R 通过：还必须核验实际 fresh Activation、截断/工具限制/取消/重连及工具资源对账，并在8/16/32实际模型并发档测量吞吐与资源。本轮这些模型验收项没有运行。
