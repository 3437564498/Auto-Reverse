# 主会话—子会话、多 Agent 执行与 DSH 兼容调研

> 初次调研：2026-10-12；V1 复核与更新：2026-10-13（Asia/Singapore）。
>
> 状态：V1 配套调研；已核查源码，尚未安装/启动 DSH 或完成实际模型兼容测试。
>
> 用户已确认 DSH 指 DeepSeek 官方 DeepSeek Harness。
>
> 对应主方案：[Android ARM64 重建方案 V1](android-arm64-so-cpp-recovery-V1.md)。

## 1. 调研问题与结论

本调研关注产品运行时的 Agent 架构。V1 已采用多 Agent、小工作包、单 Agent 少量任务和可配置 32 路并发；DSH 定制插件承担所需能力。

需要回答：

1. 大阶段如何进一步切成能独立交付的工作包？
2. 主会话、子会话、工作包、尝试、候选和证明如何对应？
3. 哪些状态属于对话历史，哪些必须由持久服务管理？
4. 如何防止多 Agent 改同一公共类型、覆盖候选或使用过期契约？
5. Agent 完成、收到消息、请求中断与业务任务成功有何区别？
6. DSH 实际提供哪些能力，哪些需要自研？

推荐方向：**持久任务 DAG + 版本化事实库 + 有边界的 Agent 会话 + 独立验收服务**。DSH 为客户端和预选 Agent Runtime；生产持久编排预选 Temporal。大多数工作采用 fresh 子会话；同一工作包内部可多轮；不同任务不共享无限增长的聊天记忆。

这些是针对本项目的设计判断，不是某个框架自动提供的完整方案。用户于 2026-10-13 批准六项优化，并补充 32 路及定制插件方向；主方案统一契约与验收，本文件保留源码能力及取舍依据。

## 2. 核查方法与 DSH 基线

下载并阅读 DSH 官方仓库的文档与相关源码。核查基线：

| 项目 | 固定值 |
|---|---|
| 仓库 | deepseek-ai/deepseek-harness |
| Commit | `d743267388641bc76f17c45ce8b4c231aed1d32c` |
| CLI 包版本 | `0.2.1-alpha.2` |
| 查询日期 | 2026-10-12；2026-10-13 再次核验相同 HEAD |
| API 状态 | 官方仓库说明公共 API 尚未稳定 |
| 实际执行 | 未安装／启动 DSH，未调用真实模型 |

[固定仓库快照](https://github.com/deepseek-ai/deepseek-harness/tree/d743267388641bc76f17c45ce8b4c231aed1d32c)、[CLI 包版本](https://github.com/deepseek-ai/deepseek-harness/blob/d743267388641bc76f17c45ce8b4c231aed1d32c/apps/cli/package.json)、[仓库 API 状态说明](https://github.com/deepseek-ai/deepseek-harness/blob/d743267388641bc76f17c45ce8b4c231aed1d32c/AGENTS.md)

本文所有“DSH 支持”均限定此核查基线；“本项目将提供”属于拟开发能力。2026-10-13 下载的当前默认分支仍是该提交，CLI 仍为 0.2.1-alpha.2。未因版本漂移改变基础选型。

## 3. DSH 子会话：三种后端不是同一种保证

### 3.1 Fresh Spawn

`dsh-subagent-spawn-in-process` 创建新的子 Session，不继承父对话；同进程复用服务。请求能力包括模型配置、结构化输出、深度限制、工具限制和 Persona。[官方说明](https://github.com/deepseek-ai/deepseek-harness/blob/d743267388641bc76f17c45ce8b4c231aed1d32c/packages/subagent/subagent-spawn-in-process/README.md)、[能力声明源码](https://github.com/deepseek-ai/deepseek-harness/blob/d743267388641bc76f17c45ce8b4c231aed1d32c/packages/subagent/subagent-spawn-in-process/src/index.ts)

本项目用途：已冻结证据和契约后，执行一个明确工作包。会话隔离不等于 OS 进程或文件权限隔离，后者仍由部署和工具代理实现。

### 3.2 Fork

Fork 复制父会话已完成回合的平衡日志前缀，不包括当前正在执行的回合；继承是创建时一次性快照，之后父会话变化不自动同步。[源码](https://github.com/deepseek-ai/deepseek-harness/blob/d743267388641bc76f17c45ce8b4c231aed1d32c/packages/subagent/subagent-fork-in-process/src/index.ts)

本项目用途：少量需要同一调查背景的第二意见。大量恢复工作默认不 Fork；其风险是复制历史假设、干扰和过期上下文。即使 Fork，工作包仍显式携带最新证据和契约版本。

### 3.3 DSH SDK 子进程后端

`dsh-subagent-dsh-sdk` 每次创建新的完整 Harness 子进程，支持模型路由配置；当前不支持父级 `outputSchema`、`toolFilter`、Persona 和数值深度限制，且不接受后续消息。[官方说明](https://github.com/deepseek-ai/deepseek-harness/blob/d743267388641bc76f17c45ce8b4c231aed1d32c/packages/subagent/subagent-dsh-sdk/README.md)、[能力声明](https://github.com/deepseek-ai/deepseek-harness/blob/d743267388641bc76f17c45ce8b4c231aed1d32c/packages/subagent/subagent-dsh-sdk/src/index.ts)

这与“宿主程序用 DSH SDK 启动一个 Runtime，然后在其中使用本地 Spawn”是不同集成方式。后者可利用本地子会话能力；前者需要在子 Runtime Profile 中配置工具和约束，并由业务层校验提交。

不允许把不支持的选项静默删掉并宣称限制仍生效。

## 4. DSH 生命周期中容易误用的语义

### 4.1 Session 与 Activation 分开

本地子 Session 可以持久保留，但每次执行是一个 Activation。结构化输出是本次 Activation 的要求，不代表以后冷恢复仍自动继承；持久描述符也不保存此前的输出 Token 预算。[Subagent 说明](https://github.com/deepseek-ai/deepseek-harness/blob/d743267388641bc76f17c45ce8b4c231aed1d32c/packages/subagent/subagent/README.md)、[持久描述符源码](https://github.com/deepseek-ai/deepseek-harness/blob/d743267388641bc76f17c45ce8b4c231aed1d32c/packages/subagent/subagent/src/descriptor.ts)

本项目每个 Attempt 绑定一次 Activation；同 Session 短修复的后续 Activation 使用新 Attempt。每次显式提供任务标识、契约、限制和提交字段；冷恢复不能只说“继续刚才任务”。

### 4.2 创建返回不是完成

模型侧 delegation 工具在接受创建后返回子 ID；最终完成另行通知。需要等待结果的程序侧调用使用 Activation 的 result。[工具说明](https://github.com/deepseek-ai/deepseek-harness/blob/d743267388641bc76f17c45ce8b4c231aed1d32c/packages/subagent/tool-subagent/README.md)

子 Agent 最终文本不是业务验收结果。`completed` 只说明执行终止方式；业务层还需校验工包、产物、版本、构建和语义。

### 4.3 消息与中断

标准本地控制支持直接父子消息；消息返回表示接受，不代表收件方已经处理。中断返回表示请求已接受，不代表进程与子孙工作已静止。当前回合中断还可能保留本地子孙工作。[控制工具说明](https://github.com/deepseek-ai/deepseek-harness/blob/d743267388641bc76f17c45ce8b4c231aed1d32c/packages/subagent/tool-subagent-control/README.md)

取消整个业务任务必须由业务取消令牌传播，并等待或隔离相关执行资源，不能只调用一次 interrupt。发布后的精确 Activation 由插件持有 handle 并调用 dispose；调用方 signal 的 startup 取消不能视为已发布运行及子孙清理保证。

### 4.4 容量不是持久队列

当前默认每棵激活树最多 8 个活动／创建中的子 Agent，根不占槽位；等待、停止中等激活仍计数。容量满时拒绝，不排队。[容量说明](https://github.com/deepseek-ai/deepseek-harness/blob/d743267388641bc76f17c45ce8b4c231aed1d32c/packages/subagent/subagent/README.md)

本项目由外部调度器排队和背压；V1 将 maxActiveSubagents 显式设为 32，并联动 Workflow 与 PTC 限制，见第 11 节。保持浅层树，禁止用全部槽位创建等待中的管理 Agent。32 是配置目标，不是官方默认值或实测吞吐。

## 5. DSH Workflow：适合有边界批次，不适合单独承载全库持久任务

Workflow 提供 `agent()`、`parallel()`、`pipeline()` 等编排。当前是前台收集，没有脚本和中间状态的 journaling／resume；进程重启不能继续原脚本执行。[Workflow 说明](https://github.com/deepseek-ai/deepseek-harness/blob/d743267388641bc76f17c45ce8b4c231aed1d32c/packages/workflow/workflow/README.md)

子 Agent、脚本和并发上限由多个配置共同影响，PTC Engine 也没有总墙钟截止时间；业务层必须补充超时与清理。[PTC Workflow](https://github.com/deepseek-ai/deepseek-harness/blob/d743267388641bc76f17c45ce8b4c231aed1d32c/packages/workflow/workflow-ptc/README.md)

本项目可以借用一小批独立工作包的 fan-out／fan-in，已完成结果及时进入持久账本。整库计划、冻结版本和恢复位置不保存在 JS 脚本变量中。

## 6. DSH MCP 与 SDK 兼容

### 6.1 MCP 客户端

支持 stdio 和 Streamable HTTP；工具呈现为服务器限定名；当前单次调用默认超时 60 秒；Task-required MCP 执行扩展未实现。长任务采用普通 `submit_job`／`get_job` 工具，提交后立即返回 job ID。[MCP 官方说明](https://github.com/deepseek-ai/deepseek-harness/blob/d743267388641bc76f17c45ce8b4c231aed1d32c/packages/mcp/mcp-client/README.md)

stdio 有启动探测，服务的 initialize／list_tools 不得启动恢复任务或产生不可重复副作用。日志写 stderr；大型二进制和 IR 不塞进模型的工具参数。

### 6.2 SDK 宿主

TypeScript SDK 通过 stdio JSON-RPC 管理 Runtime，提供 Session、事件和生命周期。其 finalResponse 是收集区间内最后的根响应，不是天然按业务任务绑定的产物证明。[SDK 说明](https://github.com/deepseek-ai/deepseek-harness/blob/d743267388641bc76f17c45ce8b4c231aed1d32c/packages/sdk/client/README.md)

因此每个根 Session 限定一个批次控制任务，提交记录必须带 task／attempt 标识，不能并发向同一 Session 塞入不相关工作，再靠最后一段文本判断结果。SDK 无 mid-turn prompt-cancel；定制插件提供专用受鉴权控制通道及 handle.dispose，失败时关闭该 Job Runtime。普通 SDK Profile 的 maxTokensAsSuccess 默认 true，V1 显式改为 false 并独立校验所有提案。

### 6.3 Experimental Agent Team

该插件提供队友与任务板，并允许更广的消息交互，但官方标记 experimental、没有稳定性保证；工具名还可能与标准控制工具冲突。[Team 工具说明](https://github.com/deepseek-ai/deepseek-harness/blob/d743267388641bc76f17c45ce8b4c231aed1d32c/packages/experimental/tool-agent-team/README.md)

首版不把它作为生产任务账本。若后续采用，用于可视化协作或特定实验，最终任务与验收状态仍由业务服务管理。

## 7. 其他预选项目对照

| 项目 | 已核查能力 | 本项目预选定位 | 不直接采用的部分 |
|---|---|---|---|
| DSH | Session、Spawn、Fork、SDK、MCP | 客户端和 Agent Runtime，优先 | Workflow 不能替代持久任务引擎 |
| Temporal | 持久 Workflow、Activity、子 Workflow | 生产持久编排优先 | 不替代 Agent 上下文与语义验证 |
| LangGraph | 子图、Checkpointer、调用级／线程级状态 | 单工作包图的备选 | 不再引入第二个全库调度器 |
| OpenAI Agents SDK | Manager-as-tools、Handoff、代码编排 | 模式参考／Runner 备选 | 不要求改用 OpenAI 模型 |
| AutoGen GraphFlow | 顺序、并行、条件、循环图 | 对照与小型验证 | 当前实验特性，不作为唯一生产恢复层 |
| CrewAI Flows | 流程与结构化状态 | 原型备选 | 不以角色组织代替 ABI／候选事务 |
| Claude Code Subagents | 独立上下文、角色／工具配置 | 上下文组织参考 | 不是 DSH 接口，也不是本项目质量证明 |
| OpenHands SDK Delegate | 软件 Agent 委托模型 | 编程工具和隔离对照 | 不直接采用默认任意 Shell 与共享树写入 |

来源：[Temporal Workflow](https://docs.temporal.io/workflow-definition)、[Temporal Activity](https://docs.temporal.io/activity-definition)、[LangGraph Subgraphs](https://docs.langchain.com/oss/python/langgraph/use-subgraphs)、[OpenAI 编排](https://openai.github.io/openai-agents-python/multi_agent/)、[AutoGen GraphFlow](https://microsoft.github.io/autogen/stable/user-guide/agentchat-user-guide/graph-flow.html)、[CrewAI Flows](https://docs.crewai.com/en/concepts/flows)、[Claude Code 子 Agent](https://code.claude.com/docs/en/sub-agents)、[OpenHands Delegate 源码](https://github.com/OpenHands/software-agent-sdk/blob/main/openhands-tools/openhands/tools/delegate/definition.py)。

### 7.1 Temporal 的采用条件

Workflow 逻辑要求确定性；模型、网络、分析工具等放到 Activity，保存其返回值用于重放。Activity 应幂等，不能宣称外部执行天然只发生一次。[Workflow 文档](https://docs.temporal.io/workflow-definition)、[Activity 文档](https://docs.temporal.io/activity-definition)

本项目映射：整库 Job 为 Workflow，有界分组可用子 Workflow，Agent 尝试及工具运行是 Activity。大证据和日志存对象库，历史仅存引用；所有提交有幂等键及版本检查。

Temporal 提供执行历史与恢复，本项目仍拥有领域任务／候选／类型版本。两者不是两套可相互独立改写的状态机：领域提交服务负责原子写入，Workflow 根据返回结果继续。

### 7.2 LangGraph 的采用条件

官方区分调用级隔离、线程级连续和完全无检查点子图；同一有状态子图的并发调用需注意状态冲突。[子图持久化](https://docs.langchain.com/oss/python/langgraph/use-subgraphs)、[持久化](https://docs.langchain.com/oss/python/langgraph/persistence)

本项目多数任务适合调用级隔离；少数持续类型调查可以使用专用线程。参考其输入输出与检查点划分，不把子图状态当作全局 ABI 真值。

### 7.3 Manager 和 Handoff

Manager-as-tools 保持上层控制，Handoff 转移对话控制。该项目需要中央质量规则和统一汇总，优先前者；Handoff 可用于客户端定位某份报告，不让它移交验收权。[Agents SDK 编排](https://openai.github.io/openai-agents-python/multi_agent/)、[Handoff](https://openai.github.io/openai-agents-python/handoffs/)

## 8. 相关文章给出的工程启示

### 8.1 多 Agent 不等于任意任务都应全并行

Anthropic 的研究系统采用 Orchestrator–Worker，也指出依赖多、需要共享上下文的代码任务较难并行。[多 Agent 研究系统](https://www.anthropic.com/engineering/multi-agent-research-system)

本项目：独立函数候选、证据查询、审查可并行；共享类型修改、ABI 冻结和最终事务必须有顺序。该文章的搜索效果不用于推断反编译成功率。

### 8.2 会话轮换需要明确交接

长任务会出现上下文耗尽、半完成和过早宣布完成。持久目标清单、进度与实际验证可以改善交接。[长任务 Harness](https://www.anthropic.com/engineering/effective-harnesses-for-long-running-agents)

本项目：下一会话获取任务快照、产物引用、未解决问题和继续条件，不能只依赖压缩聊天摘要。

### 8.3 上下文管理不是少给证据

Context Engineering 强调检索、结构化记忆和子 Agent 的独立上下文。[上下文工程](https://www.anthropic.com/engineering/effective-context-engineering-for-ai-agents)

本项目完整保留证据；按工包提供必需部分并支持扩展读取。摘要是索引，不能替代影响语义的指令、边和内存副作用。

### 8.4 大规模代码协作需要独立检查

并行构建编译器的实践可用于参考任务分解、环境和质量反馈，但其执行式测试不可原样进入本项目的纯静态恢复流程。[并行编译器实践](https://www.anthropic.com/engineering/building-c-compiler)

### 8.5 拓扑和协调成本需要实测

Google 的研究对比多种 Agent 拓扑，显示并行任务和顺序任务对协调方式的需求不同。[Agent 系统扩展研究](https://research.google/blog/towards-a-science-of-scaling-agent-systems-when-and-why-agent-systems-work/)

本项目验证浅层、分层、多个独立候选池等配置，比较质量、冲突、延迟和错误接受，而不是只比较 Agent 数量。

## 9. 最终预选组合

```text
用户 DSH 客户端
  → MCP Job Gateway
  → Recovery 领域服务和持久任务账本
  → Durable Orchestrator（生产预选 Temporal）
  → DSH Runner Adapter
  → 有边界的根批次 Session + 定制 Recovery 插件
  → 最多 32 路 Fresh 工作子 Activation，各自一份小工作包
  → 独立构建、ABI、语义检查与候选提交
```

- M0 可以用单机持久队列验证接口，但重启恢复是必需功能；不以进程内数组替代。
- DSH Native Spawn 为首选子会话模式。
- 默认一个 Agent 一份小工作包、一种候选方向；完成或上下文压力时轮换。同版本短修复可同 Session 的新 Activation，身份与限制重新绑定；输入/角色变化后新 Session。
- 单 Runtime 一次只承载同 Job 的一批任务，后端配额控制全部 Runtime 的工作者总数；逐项提交不等整批结束。
- 定制插件是正式实施模块；原生 Workflow 只作为可选可信批次适配，不持有业务真值。
- 不引入多个互相竞争的全局 Supervisor。
- DSH Team 插件、完整原生远程任务树 UI、第三方 Runner 留作后续评估。

## 10. 尚需落地验证的事项

| 事项 | 当前状态 | 后续验证 |
|---|---|---|
| DSH 客户端普通 MCP | 文档／源码支持 | 真实 stdio 与 HTTP 握手 |
| Native Spawn 结构化结果 | 能力代码已核查 | 成功、截断、错误 Schema |
| 冷恢复限制重建 | 描述符已核查 | 每次尝试重新应用要求 |
| 工作包与 Session ID 映射 | 本项目设计 | 事件和产物关联测试 |
| 客户端断开任务继续 | 持久服务设计 | 杀客户端／重连 |
| 容量和取消清理 | 代码／文档核查 | 饱和、等待、停止及子孙清理 |
| DSH UI 显示远程 Agent | 尚未实现 | 自研投影，不伪装本地 Session |
| 模型与 SDK 版本 | 固定源码基线 | 固定可安装版本并真实预检 |

研究结论不能代替这些兼容测试。本轮仅编写方案，不宣称已经支持 DSH 成品运行。


## 11. 32 路配置：三个独立限制与业务配额

用户已确认可调整 Workflow 并发到32。固定源码表明必须同时考虑：

| 层 | 核查事实 | V1 策略 |
|---|---|---|
| Workflow maxConcurrentAgents | 默认0自动估算，源码 `min(16, max(1, cores-2))` | 若启用显式32 |
| Subagent maxActiveSubagents | 默认8，每棵Activation树；根不占槽，停止中仍计数 | 显式32，浅层，清理后归还 |
| PTC maxPendingCalls | 默认128，child启动/结果等待/清理共享host calls | 初始128，容量实验核查headroom |
| Workflow maxTotalAgents | 默认1000，单run累计创建次数，不是并发 | V1有界批次建议64，续批不扩大单Agent职责 |
| ToolRuntime maxParallelSubCalls | PTC工具模式的独立限制，默认10 | 工作者默认native模式；不与32路worker混淆 |
| 领域/Runner配额 | 不由DSH跨Runtime提供 | 单机初始全局32，24恢复+8审查/修复/补证据可借用 |

配置片段不是可直接安装的完整Profile：

```yaml
- name: '@deepseek-ai/dsh-subagent'
  config:
    maxActiveSubagents: 32
    maxDepth: 1
- name: '@deepseek-ai/dsh-workflow-ptc'
  config:
    provider: spawn
    maxConcurrentAgents: 32
    maxTotalAgents: 64
    maxItemsPerCall: 64
- name: '@deepseek-ai/dsh-ptc-runtime-node'
  config:
    maxPendingCalls: 128
- name: '@deepseek-ai/dsh-tools'
  config:
    mode: native
- name: '@deepseek-ai/dsh-sdk-jsonrpc-server'
  config:
    maxTokensAsSuccess: false
```

已有Profile覆盖对应行，不重复挂载服务。首选定制BatchRunner的程序侧 fan-out 不受 Workflow 配置自动约束，插件自己执行32路配额；若复用 Workflow 才启用Workflow/PTC相关行。程序侧启动还要显式深度/工具限制，不能只写 maxDepth=1。

32路为共享上限：恢复、审查、修复和补证据合计不超过32；不是32+8。运行中的后端批次最多一个根，一个Agent一工作包，通常一函数一候选；证据全量保存，32–64K上下文是软组织目标而非截断许可。

额外任务入持久队列。Ghidra、构建、Solver、模型请求并发各有单独资源配额。正式验收8/16/32档，比较质量、未知、上下文峰值、Token、尾延迟、RSS及清理，不承诺32倍吞吐。

来源：[Workflow字段与自动上限](https://github.com/deepseek-ai/deepseek-harness/blob/d743267388641bc76f17c45ce8b4c231aed1d32c/packages/workflow/workflow-ptc/src/index.ts)、[Workflow通道关系](https://github.com/deepseek-ai/deepseek-harness/blob/d743267388641bc76f17c45ce8b4c231aed1d32c/packages/workflow/workflow-ptc/README.md)、[PTC配置](https://github.com/deepseek-ai/deepseek-harness/blob/d743267388641bc76f17c45ce8b4c231aed1d32c/packages/ptc-runtime/ptc-runtime-node/README.md)、[Subagent默认](https://github.com/deepseek-ai/deepseek-harness/blob/d743267388641bc76f17c45ce8b4c231aed1d32c/packages/subagent/subagent/README.md)、[ToolRuntime](https://github.com/deepseek-ai/deepseek-harness/blob/d743267388641bc76f17c45ce8b4c231aed1d32c/packages/core/tools/README.md)。

## 12. 定制插件路径与原生 Workflow 的参数边界

官方插件通过 Cordis Context 注册服务与工具，依赖通过 inject 声明，不依靠YAML行顺序。defineTool/ctx.tools.register负责typed工具；restrict提供作用域可见集，guard提供单调拒绝，tools/result捕获最终审计。[插件教程](https://github.com/deepseek-ai/deepseek-harness/blob/d743267388641bc76f17c45ce8b4c231aed1d32c/docs/cordis-tutorial/01-first-plugin.md)、[扩展机制](https://github.com/deepseek-ai/deepseek-harness/blob/d743267388641bc76f17c45ce8b4c231aed1d32c/docs/cookbook/extension-cookbook.md)

V1拟开发模块：TaskContext、EvidenceTools、ProposalTools、BatchRunner、StaticPolicy、Control/Audit。任务Agent只调查并提出候选，不编辑验收规则；工具代理从真实Agent/Attempt绑定身份，scope不是模型填写的权限凭证。完整设计见主方案第20—24节。

首选BatchRunner直接 startActivation，显式outputSchema、toolFilter、Persona、深度、路由及caller delivery，保存精确handle；根只调用 run_recovery_batch(batch_ref)，服务冻结计划。不是通过自由JS代码让模型决定任意排程。

核查 Workflow agent()只支持 label/phase/schema/provider/model，host未转发逐子的toolFilter/Persona/maxDepth。若复用Workflow，使用固定可信脚本、专用Profile和受控工具代理，或经验证定制适配；不能传不支持参数后静默省略限制。[参数源码](https://github.com/deepseek-ai/deepseek-harness/blob/d743267388641bc76f17c45ce8b4c231aed1d32c/packages/workflow/workflow-ptc/src/runtime.ts)、[启动源码](https://github.com/deepseek-ai/deepseek-harness/blob/d743267388641bc76f17c45ce8b4c231aed1d32c/packages/workflow/workflow-ptc/src/host.ts)

原生Workflow/Code Mode的Node VM不是安全边界，文件限制不限制所有网络/子进程行为。Worker使用native工具模式、根/子均无任意Shell或动态插件执行；可选Workflow脚本只由受信插件物化并结合进程/文件/网络策略。[PTC边界](https://github.com/deepseek-ai/deepseek-harness/blob/d743267388641bc76f17c45ce8b4c231aed1d32c/packages/ptc-runtime/ptc-runtime-node/README.md)

restrict对继承的全局工具做mask，子作用域工具仍可见。部署需核查实际schema/lookup并对新增作用域工具实施guard；允许本地outputSchema要求的structured_output终结工具，避免政策误拦完成。其记录不是业务等价通过。[结构化终结工具](https://github.com/deepseek-ai/deepseek-harness/blob/d743267388641bc76f17c45ce8b4c231aed1d32c/packages/subagent/subagent/src/structured.ts)

定制控制通道为独立鉴权IPC/端点，不假设SDK任意request方法可扩展。取消先停派发/拒绝过期提交，然后精确dispose并确认子孙和工具资源；失败关闭该Job Runtime，清理未确认则隔离并占用容量。不同Job不共享同一运行批次，避免进程关闭影响别的Job。

sdk-minimal默认含持久Shell且没有Subagent，不直接作为恢复Profile；普通sdk默认maxTokensAsSuccess=true，配置false只解决传输状态，还需领域提案校验。[sdk-minimal](https://github.com/deepseek-ai/deepseek-harness/blob/d743267388641bc76f17c45ce8b4c231aed1d32c/packages/bundle/sdk-minimal/README.md)、[sdk默认](https://github.com/deepseek-ai/deepseek-harness/blob/d743267388641bc76f17c45ce8b4c231aed1d32c/packages/bundle/sdk-app/cordis.patch.yml)

发布前固定Profile/插件版本和最终能力指纹，运行期不让Agent热装插件扩权。不修改DSH核心持久日志格式；UI增强从业务事件投影。

## 13. V1 补充验收与复核状态

| 事项 | V1验证要求 | 当前事实 |
|---|---|---|
| 32路容量联动 | 有效Profile值、全局配额、32+排队、清理占位 | 字段/源码已核查，未压测 |
| 一Agent少量任务 | 单包/单候选绑定、完成释放、上下文软目标/完读记录 | 设计契约已加入 |
| 定制插件/guard | 作用域、依赖就绪、提交代理、单调拒绝、禁止Shell | 官方扩展点已核查，插件尚未开发 |
| 截断 | maxTokensAsSuccess=false，max-tokens/length不登记为成功产物 | 默认行为已核查，尚未联调 |
| 取消 | startup/published/commit窗口，handle.dispose/Runtime关闭与工具清理 | 协议和生命周期已核查，尚未实验 |
| 提案原子性 | 对象写入→DB回执/outbox，丢回报可重放，迟到写拒绝 | 领域设计，尚未实现 |
| 持久规模 | 子Workflow/Continue-As-New、对象引用、有限历史 | 官方Temporal资料复核，尚未压测 |

M0-R先两个会话验证受控运行，再逐步8/16/32；M0-S独立核查ARM64精确语义子集。上述支持声明不代替安装/模型/共享库恢复实验，原有团队/工期估算在M0后重新校准。

初稿配套调研另存[历史记录](snapshots/main-child-agent-DSH-RESEARCH-INITIAL-2026-10-12.md)。当前主方案为V1，0.2的6/8容量建议和旧状态例子仅保留历史，不作为现行策略。
