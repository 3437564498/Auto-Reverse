# M0 实施记录

日期：2026-10-13（Asia/Singapore）。设计基线：V1，远端提交 `30c31f9`。

用户要求开始实际多 Agent 开发。本轮首先同步远端 V1，再按冻结接口拆分工包；历史草稿保持不变。

## 本轮验证结果

- Python：`pytest -q`，**513 通过**，包含 300 个真实 SMT 非等价常量变异，以及独立 ISA/服务竞态回归。
- DSH：`npm test`，严格 TypeScript 构建及 **19 项测试通过**；含官方 Cordis 工具注册/作用域/guard 测试，其余生命周期与容量使用明确的注入测试 seam。
- Ruff、依赖一致性、共享 Schema 和 Git 空白检查通过；Python wheel 可构建。
- 真实编译微库：`x+7` 对 `7+x` 为声明输入域下 EXACT_EQUIVALENT，`x+8` 为 DIFFERENT；该验证没有执行库。
- C++17 helpers：native 与通用 AArch64-musl compile-only 通过；Android C++ sysroot/NDK 验证仍待完成。

独立审查发现并修复了代码页与符号数据内存混用导致的误接受、RET 内部跳转被截断、取消窗口中新关联产物、分页不前进循环和 MCP 工作者分页参数不一致。回归保留在仓库。MCP 依赖发出一条 settings forward-reference 警告，协议测试通过；该第三方警告不代表恢复能力验收。

| 工包 | 交付代码 | 验证与边界 |
|---|---|---|
| 持久领域服务 | `domain.py` | SQLite Job/DAG/Attempt、版本检查、共享 32 个资源名额、回执/Outbox、取消/隔离；完成与质量分开 |
| 输入与证据 | `intake.py`、`artifacts.py` | ELF64 LE AArch64 ET_DYN 有界体检、真实函数字节、CAS 指纹、不可变引用、明确分页；不执行 resolver/初始化 |
| 静态语义 | `semantics.py`、`capabilities.py` | Capstone 原指令能力检查、来源 IR、Z3 位向量及受控字节内存、返回路径/前提义务；按明确范围报告 |
| DSH 适配 | `integrations/dsh/` | 固定官方包、Cordis 插件、Fresh Activation、角色工具策略、完整共享 Schema、精确清理；领域客户端和宿主由注入接口提供 |
| 主 Agent 集成 | `contracts.py`、`service.py`、`cli.py`、`mcp_server.py` | 共用 JSON Schema、策略校验、A0 体检、持久队列 worker、真实 MCP stdio/HTTP 协议验证 |
| 独立验收 | `test_semantic_review.py` | 独立正反公式与边界审查；发现的问题纳入回归，不以模型一致意见替代验证 |

## 可复现的静态微样本

```bash
.venv/bin/python -m pip install ziglang==0.15.1
.venv/bin/python scripts/build_micro_samples.py
.venv/bin/arm64-recover analyze --binary work/static-samples/liboriginal.so --output work/intake-report
.venv/bin/arm64-recover verify --original work/static-samples/liboriginal.so \
  --candidate work/static-samples/libequivalent.so --function add_seven
.venv/bin/arm64-recover verify --original work/static-samples/liboriginal.so \
  --candidate work/static-samples/libmutated.so --function add_seven
```

编译器为 Zig 0.15.1 自带 Clang，目标 `aarch64-linux-android`，`-shared -nostdlib -fPIC -O2`。三份 freestanding C++ 样本分别表达 `x+7`、`7+x` 和 `x+8`。脚本只编译链接，生成源文件/机器产物指纹与命令清单；分析器读取 ELF 符号对应的机器字节，不加载或执行库。

该实验验证受限函数机器语义比较链路。它没有采用 Android NDK/sysroot，也不代表 Android 运行库、加载环境、设备或完整 C++ 重建验收。任一 EXACT 记录都绑定观察契约与全部前提；默认检查返回值、SP、核心 callee-saved 寄存器、返回目标和模型内内存，`whole_program_equivalence=false`。入口 X30 受明确记录的函数调用域限制，必须位于两侧代码范围外；每条实际 RET 都必须证明不会跳回这些范围，内部目标或未闭合路径保留 UNKNOWN，显式内部入口 LR 形成 INVALID_PRECONDITION。范围边界是已证明的外部返回事件，后续代码效果不在该记录范围内。

## 当前未完成的退出条件

- M0-S：Ghidra 自动导入与结构化 Raw P-code 仍待接入；目前 IR 来自本项目原指令解码与语义降低。NDK 实际构建/ABI 链路未验收。
- M0-R：插件可构建并进行故障测试，但 Python 领域服务与真实 DSH 宿主尚未接线；尚未配置模型凭据并运行两个真实 DSH 模型工作子会话。
- 单 Agent 少量任务和 32 个共享名额已有契约/账本验证；8/16/32 模型并发、吞吐、资源用量尚未测量。
- ELF Profile 记录已观察特性及缺口，尚未应用 Packed/RELR 重定位或解析完整 JNI/C++ 类型/入口闭包。
- 自动 C++ 候选恢复、多候选独立构建、依赖失效闭包、完整工程物化、生产 Temporal 与 UI 增强是后续工包。

## 后续开发依赖

1. 统一冻结批次任务与租约发放协议，将 TS DomainClient 接入真实领域账本，并配置固定 DSH 专用 Runtime/Profile 与受鉴权控制通道。
2. 在固定 Android NDK 和 Ghidra 基线上验证导入、Raw IR 来源、实际候选编译及 ABI 检查；继续独立 ISA/语义对照。
3. 使用两个真实 DSH Fresh 工作者完成 M0-R 正向、截断、工具限制、取消及重连实验。
4. 两项 M0 退出条件通过后冻结 M1 子集与样本，再开发 C++ 恢复/类型事务/候选检查闭环；保持纯静态和独立质量门禁。
