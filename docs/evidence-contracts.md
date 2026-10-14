# 证据交付与原始标量声明约束

本批接通实际补证据提案的宿主消费，并提供原始 ELF 自带 DWARF 的有界声明约束冻结。证据任务不再仅停留在 `RESULT_PROPOSED`；模型的辅助发现与可信校验结果分别保存。原始调试声明并不证明机器码遵守该声明，整体调用 ABI、候选源码类型匹配和整库集成仍待验证。

## 补证据交付

当前只消费修复反馈生成的单函数 `EVIDENCE_READY` 工包。工作者取得真实 lease、绑定 Session/Activation、完整读取 manifest 中引用的证据，然后使用已有 `candidate_stage` 和 Proposal 提交以下六字段 JSON：

```json
{
  "schema_version": 1,
  "kind": "evidence_gap",
  "symbol": "load_word",
  "findings": [],
  "gaps": ["缺少经过独立验证的地址区域与访存前提。"],
  "evidence_refs": ["sha256:<实际已读取证据的 SHA256>"]
}
```

`kind` 也可以是 `scoped_evidence`，此时至少提供一条 finding。两类交付都必须引用至少一份完整实际送达的授权证据，Proposal 与 envelope 的引用集合一致。findings/gaps/ref 列表各最多 64 项；每条说明最多 4096 字符。只读最后一页、只自报引用、重复引用相同内容的 metadata 别名、额外质量/前提字段或重复 JSON key 均不会被接受。

可信宿主可以运行：

```bash
arm64-recover --state-dir <state> consume-evidence \
  --execution-key <真实回执的 execution_key> --artifact-ref <真实候选引用>
arm64-recover --state-dir <state> postprocess-candidates <job_id>
arm64-recover --state-dir <state> list-evidence-deliveries <job_id>
```

后处理每次最多检查 `max_activities` 份证据提案，并独立处理同样有界的验证报告。未确认清理的交付列为 `evidence_deferred`，无效交付列为 `evidence_rejected`，等待宿主处理；不会自动再租用工作者来重试无效提案。

服务核验真实 receipt、staged CAS、当前 snapshot/revision/epoch、单函数 scope、父反馈及全部祖先报告/proof/工具指纹，还核验 worker 与相关 Tool Activity 的清理状态。成功时在一次事务中保存交付、CAS 引用、事件/Outbox，并将 Task 分类为 `COMPLETED`。相同交付重放不增加事件，历史数据保留，失效后只读返回 `current=false`。

消费结果为 `AUXILIARY_RECORDED` 或 `GAP_RECORDED`；findings 的权限始终是 `UNTRUSTED_AUXILIARY`。当前消费不修改可信事实、访存前提、ABI 或 Job 质量，也不自动派发新修复。把辅助发现转为独立核验的 IR/类型/区域事实并继续恢复，仍是后续工作。

## 原始 DWARF 声明与版本冻结

```bash
arm64-recover inspect-scalar-abi --binary <original.so> --function <symbol>
arm64-recover --state-dir <state> freeze-scalar-abi \
  --execution-key <type_abi 回执的 execution_key> \
  --artifact-ref <真实候选引用> --expected-revision <当前 revision>
arm64-recover --state-dir <state> get-abi-contracts <job_id>
arm64-recover --state-dir <state> list-abi-contracts <job_id>
```

`type_abi` 工作者通过现有 JSON staging/Proposal 提交精确五字段约束：

```json
{
  "schema_version": 1,
  "kind": "scalar_abi_constraints",
  "symbol": "add_seven",
  "parameter_widths": [64],
  "return_width": 64
}
```

宿主从 Job 注册的原始 ELF 独立读取 DWARF，不能使用模型另送的 debug 数据或事实替代。成功状态仅为 `DECLARED_DEBUG_SHAPE`，始终保留 `original_calling_abi_verified=false`。当前 profile 的范围如下：

| 支持 | 未支持时的处理 |
|---|---|
| 唯一 plain C 动态导出，原始代码地址/长度与 DWARF 定义精确对应 | 无定义、歧义、区间不匹配、variant PCS → UNKNOWN |
| 标准 LP64 unsigned 32/64 基础类型及有界 typedef/const/volatile 包装 | signed、指针、FP、聚合、`_BitInt` 等扩展 → UNKNOWN |
| 最多 8 个寄存器参数，明确零参数声明可支持 | 变参、隐式参数、栈参数、JNI/C++ linkage → UNKNOWN |
| ELF 内完整的有界 DWARF 2–5 普通编译单元 | stripped、损坏、超预算、压缩、split/外部 debug、继承原型 → UNKNOWN |

类型名称只用于排除未建模扩展；宽度仍由 unsigned 编码、存储和位宽等原始声明属性共同约束。不会根据函数名或指令猜原型。没有打开外部 debuglink 文件，更不会装载原库。

freeze 需要已提交且已确认清理的真实 `type_abi` Attempt。UNKNOWN 原始声明或提议与原始形状不一致时，不发布合同、不推进 revision。成功则原子核验 `expected_revision`，推进全局 revision，并冻结原始输入、证据/CAS 与解析器指纹。当前最多保存 64 个 symbol；合法历史合同可随相同输入的后续 revision 保留。

版本推进时旧 Task epoch 全部失效，非终态任务变为 `SUPERSEDED`，旧验证活动取消，当前候选证明失效；运行中或隔离的 worker/tool 容量保留到真实确认清理。Job 质量重置为 UNKNOWN。历史 receipt、候选和报告仍可读取。新的生成/验证需要在新 revision 下重新规划工包；当前不会自动物化公共头文件或证明候选签名符合约束。

公开 MCP 新增 `get_abi_contracts`、`list_abi_contracts`、`get_evidence_delivery`、`list_evidence_deliveries` 四个只读工具，读取时不安装宿主可选表、不修改事件。worker `contract_read` 返回两类辅助交付 schema 及当前声明合同。消费、freeze 和质量更新权限均属于可信宿主。

## 实际静态样例

```bash
.venv/bin/python scripts/run_evidence_contract_sample.py \
  --ndk-root work/tools/android-ndk-r27c --output work/evidence-contract-new
```

脚本只编译固定可信 fixture、解析 ELF/DWARF 和比较机器码。原始样本增加 `-g` 使用独立可信编译步骤，模型候选的受控构建参数保持固定。实际 `load_word` 缺少访存区域，局部语义保持 UNKNOWN；真实 gap 提案被消费，重放没有新交付或修复。`add_seven(uint64)->uint64` 的声明经原始 debug 校验冻结到 revision 2，旧交付转为历史，旧来源不能取得新的验证授权，整体 ABI 仍 UNKNOWN。

确定性 fixture 的模型调用为 0，原库和候选库均未执行；这个样例不代替真实 DSH 模型或完整 V1 验收。
