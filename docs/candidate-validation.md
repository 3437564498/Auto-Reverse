# 候选提交与持久独立验收

更新：2026-10-14（Asia/Singapore）。本页描述单机静态工具活动，不代表真实模型验收或完整 M1 通过。

Agent 的提案只登记为 `RECORDED`。领域服务保存真实回执后，由可信宿主单独排队构建和验证；Agent 不获得 Shell、编译参数、验收结果写入或资源清理确认权限。

## 源码候选格式

`contract_read` 返回 `source_candidate_contract`，同一 Schema 保存于 `schemas/cpp-source-candidate.schema.json`。恢复/修复工作者将以下四字段 JSON 文本提交给 `candidate_stage`，再使用实际返回的 artifact_ref 提交 Proposal：

```json
{
  "schema_version": 1,
  "kind": "cpp_source",
  "symbol": "add_seven",
  "source": "extern \"C\" unsigned long long add_seven(unsigned long long x) { return x + 7ULL; }"
}
```

示例原型只是显式选择的标量寄存器模型，不是原类型恢复的证据。候选 envelope 不允许 quality、flags、路径或额外字段；重复 JSON key、错误版本和与冻结范围不同的 symbol 被拒绝。stage 包含 JSON 编码后的总大小上限，源码仍须通过受控构建的 include/预处理规则。

## 宿主与公开读取接口

可信宿主取得已提交的 execution_key 和 candidate_ref 后，使用固定配置排队。函数名必须在该 WorkPackage 的 function_ids 中；没有进入真实回执的 staged 对象不能验证。

```bash
.venv/bin/arm64-recover --state-dir work/domain queue-validation \
  --execution-key <recorded-execution-key> --candidate-ref <recorded-candidate-ref> \
  --function add_seven --idempotency-key <host-request-key> \
  --ndk-root work/tools/android-ndk-r27c --soname libmicro.so
.venv/bin/arm64-recover --state-dir work/domain validation-worker --once \
  --ndk-root work/tools/android-ndk-r27c --soname libmicro.so
.venv/bin/arm64-recover --state-dir work/domain list-validations <job-id>
.venv/bin/arm64-recover --state-dir work/domain get-validation <job-id> <activity-id>
```

worker 必须使用与排队时一致的参数和所选工具文件。配置或同路径工具内容改变，不会复用旧成功。普通 MCP 只公开 `list_validations`、`get_validation` 和有界 `read_validation_report`；当前有效产物仍可经 `list_artifacts` / `read_artifact` 读取。读操作不会启动编译器，也不允许模型排队或确认清理。所有读取核对 Job 归属。

## 持久状态与资源

每个活动冻结 Receipt → Proposal → Attempt → Task → Job 的真实身份、epoch、输入快照和契约，以及 source、input、host config、helper 和所选 NDK 工具文件的哈希。相同提案/候选/函数只创建一个活动；相同幂等键不能改变冻结输入。

SQLite 事务让两个宿主争抢一个 READY 活动时只有一个取得 claim。构建使用新目录，实际源和 ELF 指纹核对后进入 CAS；ABI、实际机器比较、报告、事件和 Outbox 持久保存。完成后重启读取同一报告，不能重新执行已完成活动。发布事务内再次核对当前版本、配置与对象哈希，旧 owner 或旧 run 不能覆盖新活动。

验证工具资源与 Agent 名额分别记录。Job 的清理状态同时聚合两者。取消 READY 活动不会启动工具；取消 RUNNING 活动先持久阻止结果发布，当前固定工具退出后完成取消。停止请求不是资源清理确认，父进程已 reap 也不自动证明子进程组结束。

运行中宿主崩溃不会自动重跑 RUNNING 活动。可信宿主使用 `quarantine_running` 隔离，并在核实旧宿主及其工具已结束后调用 `confirm_cleanup(confirmed=True, requeue=True)`；未确认保持资源占用，不能重排。该 API 是宿主控制，公开 MCP 不暴露。Linux 组内 zombie 已终止，但 escaped session 的完整容器隔离尚未实现，工具仍限于固定可信编译器。

取消或版本失效的诊断保存为 Activity 的历史报告，可通过 `read_validation_report` 分页读取；旧成功产物不会加入 Job 的当前输出。Task 已交付但独立验证仍 READY/RUNNING/QUARANTINED 时，Job 不能提前 COMPLETED。

## 结果的范围

`compare-abi` 对照原始和候选 ELF 的 SONAME、DT_NEEDED、导出属性、OBJECT/TLS 尺寸、完整 st_other（含 variant PCS）和动态符号版本。函数代码长度改变可以合法；导出元数据缺失或不完整不能以空集合通过。选择一个函数时仍保存原库全部导出分母和未选缺口。结构 PASS 不证明原型、对象布局、依赖实现或完整调用 ABI。

独立验证比较实际编译后的机器码，记录局部 `local_semantic`，整体 `semantic` 保持 UNKNOWN。源码 UB 的完整证明、原型/调用 ABI 与入口/全局闭包尚未完成，不能把局部机器等价当成 C++ 或整库验收。未实际编译最高 A0；实际源和 ELF 绑定通过后最高 A1，出现 DIFFERENT 的源码候选仍可保存为 A1 实际构建产物，但不成为已验收等价实现。Proposal 保持 RECORDED，Job quality 不自动提升。

## 无模型的实际闭环样本

```bash
.venv/bin/python scripts/run_candidate_validation_sample.py \
  --ndk-root work/tools/android-ndk-r27c --output work/validation-sample-new
```

脚本编译固定 Android 微库，从原机器字节生成候选，再通过真实 lease/binding/stage/receipt 路径提交等价和错误常量两种源码。随后独立 NDK 编译、ABI 结构对照及 SMT 分类，验证幂等和重启读取。Provider 明确为 deterministic-static-fixture，模型调用数为零；不把设施集成当成真实 DSH Fresh 工作者验收。

后续仍需实现：有界修复/补证据反馈工包、最佳候选与当前质量聚合、完整入口/全库清单、工具恢复的宿主资源审计及真实模型验收。
