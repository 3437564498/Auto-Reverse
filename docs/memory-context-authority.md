# 宿主内存假设权威：M1 第一阶段

本阶段提供可信宿主登记来源、冻结和撤销固定内存假设的账本。输出为 **A0 / ASSUMED**，`environment_proved=false`；候选、选择、工程和 FINAL 尚不消费它，`proof_consumption_implemented=false`。现有 `load_word` 即使已经登记假设，实际重新编译后的机器比较仍为 UNKNOWN。完整 M1 条件验证链路和完整 V1 尚未通过。

## 接受的有限范围

每份上下文绑定一个安全命名的普通导出函数、原 ELF 中唯一且完整的 file-backed 函数范围，以及该函数当前有效的 unsigned64 首参数声明。声明须先经过真实 `type_abi` 租约、交付和原始 DWARF 核验。unsigned64 只提供有限标量形状，不证明地址有效、指针来源、调用者对象或原始调用 ABI。

宿主明确指定 X0 的固定地址，以及从该地址开始的一个普通 normal-memory 区域。地址只能使用 `0x` 加 16 位小写十六进制；大小为 1–4096 的 JSON 整数，权限为 `r` 或 `rw`。区域不能回绕或覆盖原库可执行区间。不接受多个区域、SP/LR/W 寄存器别名、写入专用区域、地址数字、布尔或浮点大小、未知字段、重复键及非有限 JSON 数。

这些范围和权限是宿主的环境假设，不从 PT_LOAD、DWARF 类型或 worker finding 自动推导。旧 `Scope.region_ids` 仍是原来的不透明字符串列表，候选源码四字段协议、机器模型、包装头文件和九份原 Schema 保持兼容。

## 宿主操作

先创建 `source.json`，记录准确域和人可读假设说明：

```json
{
  "schema_version": 1,
  "kind": "host_memory_assumption_source",
  "symbol": "load_word",
  "address": {"register": "x0", "value": "0x0000000040000000"},
  "region": {"base": "0x0000000040000000", "size": 64, "permissions": "r"},
  "statement": "宿主明确假设此固定地址起的 64 字节是可读普通内存；物理环境与指针来源尚未证明。"
}
```

```bash
arm64-recover --state-dir STATE register-memory-context-source \
  --job JOB --source source.json --idempotency-key source-1
```

登记返回 `source_ref`，不推进 revision。宿主账本、Job artifact 登记和 `memory.source_registered` 事件共同形成来源权威；仅向 CAS 写入同形 JSON 或通过 worker 交付它不能授权冻结。文档最多 64 KiB，说明最多 8192 字符。

将返回的真实 `source_ref` 写进 `request.json`；地址、区域和函数必须与已登记来源完全相同：

```json
{
  "schema_version": 1,
  "kind": "host_fixed_normal_memory_assumption",
  "symbol": "load_word",
  "address": {"register": "x0", "value": "0x0000000040000000"},
  "region": {"base": "0x0000000040000000", "size": 64, "permissions": "r"},
  "source_ref": "sha256:替换成登记返回的64位小写摘要"
}
```

```bash
arm64-recover --state-dir STATE freeze-memory-context \
  --job JOB --request request.json --expected-revision 2 --idempotency-key context-1
arm64-recover --state-dir STATE get-memory-contexts JOB
arm64-recover --state-dir STATE list-memory-context-history JOB --limit 100
arm64-recover --state-dir STATE revoke-memory-context \
  --job JOB --symbol load_word --expected-revision 3 --idempotency-key revoke-1
```

这里的 revision 数字仅对应样例：标量冻结 1→2、内存冻结 2→3、撤销 3→4。实际使用当前 Job 版本。只允许 QUEUED/RUNNING Job 的新写入；每 Job 最多 64 个当前函数上下文。

同键同载荷返回原回执，不新增事件或 revision；同键异载荷拒绝。撤销后重放旧冻结请求只返回历史回执，不恢复 current。历史分页使用返回的 `next_cursor`。

## 事务、失效与纯读

冻结在同一数据库事务中登记不可变 CAS 产物、current map、宿主事件和幂等回执，并推进全局 contract revision。中立版本隔离逻辑同时更新任务 epoch、使旧非终态任务失效、请求取消三种工具活动并将当前质量降为 UNKNOWN。它无需伪造一个 `type_abi` Task；旧 ABI 冻结仍先完成真实交付任务，再复用同一隔离逻辑。

CAS 写后会复读内容和摘要，并重新快照来源与依赖。事件或 CAS 故障不会提交半份 current 或半次 revision；无账本引用的 CAS 对象不构成权威。已占用的 worker 或工具资源，只有实际清理确认后才归还。

current 重新核对原输入、policy、函数范围和字节、当前标量契约、来源 CAS、Job 登记、宿主发布事件、规范化域、机器/观察 profile 和实现指纹。最新冻结或撤销事件阻止旧 map 复活；比较保留 JSON 类型，`false`、`0`、`0.0` 不能互相代替。无关函数推进全局版本时，依赖未变的上下文仍可 current；依赖标量被替换或原字节、来源、实现变化时失效，历史继续可读。

公共 service/CLI 和新增两个 MCP 工具 `get_memory_contexts`、`list_memory_context_history` 仅查询。它们不安装可选表、不写事件、不启动编译器或 Solver，支持 `PRAGMA query_only=ON`。MCP 和 worker RPC 不暴露登记、冻结、撤销操作。权威指纹绑定解析器、版本隔离和机器/观察 profile，不绑定 NDK 的安装路径；以后消费证明时还需单独绑定实际工具链。

## 复现与后续范围

```bash
python scripts/run_memory_context_sample.py \
  --ndk-root work/tools/android-ndk-r27c --output work/memory-context-acceptance
```

样例使用实际固定 NDK，比较 normal O2 与同源码 DWARF 原函数字节，走真实标量交付、宿主登记和冻结，再分别实际编译两个候选。12 项检查涵盖冻结前后 UNKNOWN、版本、幂等、撤销后旧回执、纯读和资源归零。CI 只上传公开 `memory-context-sample.json`，不上传私有 `state/`、原库、候选 ELF 或凭据。原库与候选始终作为数据处理，模型调用数为 0。

本批新增 253 项：版本隔离 21、内存服务 52、独立攻击 136、接口 44；另有真实命令样例。275 项相关组合回归已实际通过，详细验收和本地环境限制见[冻结记录](acceptance/2026-10-19-memory-context-authority.json)。完整远端结果以当前 PR 的 Checks 和实际下载产物核对为准。

本地广泛回归实际为4545 passed、1 skipped、2 deselected（1343.69秒）；补齐本地NDK路径后，唯一跳过项另行复测1 passed，合计4546项实际通过。两项MCP传输受沙箱限制仍未验收；离线Node为28通过、2个依赖socket的用例失败，分支守卫13项通过。固定NDK/Ghidra矩阵60/60与8个既有真实命令样例通过；wheel的43模块/3资源和9旧Schema逐字节一致。GitHub写工具返回 `MCP tool call requires approval, but approval policy is never`，本批尚未推送、未创建PR、未运行完整远端CI，不能标记完整验收通过。独立样例在广泛回归后加强了AST签名、实际build/cleanup和机器UNKNOWN原因断言；生产与测试文件未改，最终真实样例已另行重跑通过。

下一阶段须一起完成候选、选择/反馈、最终链接新字节、ZIP 和 FINAL/current 对可信上下文的消费。低层原始 EXACT 必须保留其精确机器模型范围，宿主环境假设应使外层质量明确条件化；不能仅接上候选就提升全工程质量。完整调用 ABI、源码 UB、指针来源、物理环境和整库语义仍是独立未决义务。
