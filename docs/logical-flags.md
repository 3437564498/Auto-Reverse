# ANDS 逻辑立即数与局部 EQ/NE 条件分支

机器模型 `arm64-m0-integer-memory-eqne-ands-4` 支持原始编码核验的 32/64 位 ANDS logical-immediate、Rd=ZR 的 TST 别名，以及严格前向、同侧完整函数范围内的 B.EQ/B.NE。实际固定 NDK O2 的 64 位变量旋转 helper 因而可以按新字节重新证明；完整 X0、SP、X19–X29、全部 modeled memory、RET 和外部 LR 条件均保持。

本机器增量没有扩展源码生成语法、原调用 ABI、边界 NZCV 观察或整库等价。后续有限 CFG2 源码扩展另见[逻辑源码恢复](logical-source-recovery.md)。寄存器/移位 ANDS/TST、BICS、BC.cond、其他条件码、后跳、调用和其他 flags 更新仍不支持。

## 编码、状态与 IR

逻辑立即数使用独立于 UBFM 的 DecodeBitMasks。它按原始 sf/N/immr/imms 核验元素宽度、连续 1 的长度、元素内旋转及重复。32 位 N=1、非法元素和全 1 元素保留 UNKNOWN。合法编码中超出元素旋转宽度的 immr 高位按 ISA 忽略，不误拒这些编码别名。

同样的原始 N=0/imms=5 在 W 中得到 63，在 X 中得到 `0x0000003f0000003f`。核验不能把 32 位掩码直接当完整 64 位值；Capstone 的负 X immediate 只接受对应宽度内的 signed/unsigned 两种表示，不允许任意整数取模冒充。原始 word、实际 mnemonic、寄存器角色、位宽、立即数、无移位/扩展/writeback 和 flags 属性分别匹配。

ANDS 真实写入目的寄存器，W 写入清零 X 高 32 位；TST 只丢弃数据结果。两者都替换全部内部 NZCV：N 是结果高位，Z 是结果为零，C/V 为 false。不能只更新 Z，或保留先前 CMP 的 C/V。后续普通寄存器修改不重算 flags。

每条可行路径的 flags 在入口未定义，只有受审 CMP 或 ANDS-immediate 可以定义。EQ/NE 选择与分支在任一路径缺少有效定义时保留 UNKNOWN。每条分支复制自己的 flags 状态，不借用其他路径。路径/指令预算耗尽、Solver 未完成或未闭合范围均不能给等价结论。

B.cond 原始 bit4 必须为零，cond 只能为 EQ/NE；BC.cond 即使打印相同条件也不接受。目标由 raw imm19 独立计算，必须为正向、对齐且属于同侧已完整解码的范围。整个原始和候选范围的所有 word 都检查，不能因某条边不可达或条件看似恒假而跳过。高地址的 Capstone signed64 目标只接受等价的有界表示，IR 和执行路径统一使用受审 uint64 目标。

IR 按 raw 记录 ANDS 的实际目的寄存器、TST 的原始输入和 NZCV，以及条件分支的目标和两条后继。固定 Capstone 对 TST 读写寄存器的误报不作为这些受审指令的权威；NZCV 仍为四位 processor state。

## 当前证明与安全边界

严格证明读取器同步新的 model 名称、工具/实现指纹和完整 flags 假设。即使重算 verification ID 和 scope hash，旧 CMP-only 定义、任意入口 NZCV、额外条件消费者或布尔/整数/浮点混淆都不能进入当前证明。模型文件变化使当前候选、工程、控制器和最终报告失效，历史证据保留；读取不重新编译、求解或写入账本。

机器 EXACT 不扩展源码 checker。任意 helper-call C++ 仍可为源码安全 UNKNOWN；已有 TST 条件样例现在通过独立 TBZ/ADD/SUB 参考字节证明机器行为，该批冻结时源码生成仍 UNKNOWN；后续 CFG2 只扩展另行受审的有限模板。固定头文件的有限定义行为论证不推广为任意 C++ 或全库 UB 证明。

## 实际验收

独立 raw oracle 枚举 16,384 个字段组合：W 有 3648 个合法编码、1302 个不同掩码，4544 个保留编码；X 有 7680/5334/512。独立对抗测试还覆盖全部 NZCV 四位、W 零扩展、别名/ZR、分支范围、未定义 flags、快照/覆盖、真实错误变异和预算。首轮发现的高地址 signed/unsigned 目标误拒已修复，并保留回归。

实际固定 NDK 编译 55 份新 ELF，83 个编译产物比较得到 **44 EXACT、37 DIFFERENT、2 UNKNOWN**；未知项分别是 LT 形态和缺少合法区域契约的访存负例。另 10 个原始指令边界及 4 个源码安全审计保持 UNKNOWN。165 次工具调用逐项确认清理，头文件未改，不执行产物。

固定矩阵从 48 扩展至 60，新增 ANDS 实际写回、X 重复掩码、TST 选择、flags 快照/覆盖、条件/掩码/位宽变异，以及未定义 flags、BC、后跳、保留编码。全部 fixture/source SHA256 固定，真实 NDK/Ghidra 对新字节交叉核验。

```bash
export AUTO_REVERSE_TEST_NDK_ROOT="$PWD/work/tools/android-ndk-r27c"
export AUTO_REVERSE_TEST_CMAKE="$PWD/.venv/bin/cmake"
export JAVA_HOME="$PWD/work/tools/jdk-21.0.8+9"
export GHIDRA_HOME="$PWD/work/tools/ghidra_11.3.2_PUBLIC"
.venv/bin/pytest -q tests/test_logical_flags.py tests/test_logical_flags_adversarial.py \
  tests/test_logical_flags_proof_boundary.py tests/test_logical_flags_compiler_acceptance.py \
  tests/test_ror_compiler_acceptance.py tests/test_static_acceptance.py
.venv/bin/python scripts/run_static_acceptance.py \
  --ndk-root work/tools/android-ndk-r27c --ghidra-home "$GHIDRA_HOME" \
  --output work/logical-flags-new
```

冻结后的完整本地回归为 **3582 passed、0 skipped、0 failed**（869.36 秒，1 条既有警告），新增 284 项已包含；输入和初轮旧预期失败均保留在[冻结验收](acceptance/2026-10-18-logical-flags.json)。当前提交远端结果另见[实施记录](implementation-status.md)与实际 GitHub Checks。所有过程只执行宿主工具；原库、候选库、目标 harness、模拟器、设备和初始化器均不执行。真实 DSH、完整 M0-S/V1、完整类型/调用 ABI 和整库闭包仍未完成。
