# ROR 独立 ISA 与 helper 验收

这批工作补强已经支持的 32/64 位 ROR 机器模型及随包 `machine_helpers.hpp`，不扩展生产语义或任意 C++ 安全能力。独立 ISA 公式、实际 helper 编译与固定原始字节矩阵分别验证，完整 M0-S 与 V1 仍需其余退出条件。

## 独立位关系

ROR 的结果第 k 位来自输入的第 `(k + r) mod width` 位。独立 oracle 用逐位置换和布尔 mux 表示该关系，不调用生产模型的移位/OR 公式或 Z3 RotateRight。变量 r 只由 amount 的低 5/6 位决定。

原始 RORV 与 EXTR 同源寄存器的立即数别名分别核对。32 位 EXTR 要求 sf=N=0 且 imms 小于 32，64 位要求 sf=N=1；不同源的通用 EXTR 不在 ROR 能力中。保留编码和不支持形式在原始、候选两侧及不可达字节中均保留 UNKNOWN。

输入寄存器、amount 和目的寄存器的旧高位都保持全符号。W 写入必须把完整 X 的高 32 位清零；ZR 读零、写入丢弃，不能当作 SP 或普通寄存器。单指令公式的帧检查与完整函数的 X0、SP、X19–X29、全部 modeled memory 和 RET 边界检查分开记录。

错误方向、amount 多取一位及保留旧 W 高半的错误数学模型必须产生 SAT；实际受支持的错误机器程序必须得到 DIFFERENT。不支持编码的 UNKNOWN 不计作精确检测到的差异。

## 随包 C++ helper

`require_word` 限定 unsigned32/64；amount mask 使 shift 位于 `[0,width-1]`。shift 为零时提前返回，不求值 `width-shift` 的移位；其余分支的两个移位量均在 `[1,width-1]`，unsigned 位运算按目标固定宽度定义。这是固定头文件与固定目标下的有限义务，不是通用源码或整库 UB 证明。

编译验收使用实际打包的头文件、固定 NDK r27c、正常 O2 C++ 和既有构建入口，不以 asm、volatile 或特殊优化参数迫使输出。每份 ELF 都提取新函数字节，与独立原始 ISA word 参考程序比较，并保留编译器、工具链、运行库、源码、头文件、ELF、函数和清理证据。编译通过不替代机器证明；Clang 输出不支持形式时仍为 UNKNOWN。

实际 r27c O2 的 `ror<uint64_t>(x,n)` 保留 ANDS 与 B.EQ 的零移位分支。在本 ROR 验收提交的旧 profile 中，这个完整函数保留 UNKNOWN，历史记录不改写。后续 [ANDS 与局部 EQ/NE 分支增量](logical-flags.md) 专门核验这两种形式后，以新的实际编译字节和新模型证明该 helper，不复用旧 UNKNOWN 或其他函数的结果。

普通 `uint32_t` 返回的源码只规定低 32 位。特别是旋转零位的身份函数，Clang 可以只生成 RET；原始 W 指令则会清零 X0 高半，两者在完整 X0 观察下可能 DIFFERENT。需要表达完整 W 写入时，使用实际 `write_w(ror<uint32_t>(...))` 返回 uint64 位模式，并保留普通 uint32 身份包装器的实际反例。不得以缩小初始域、放宽观察集合或调用 ABI 假设隐藏这个差异。

## 固定静态矩阵

新增 12 个 ROR 场景，总计 48 个。六个正例覆盖变量 W/X、立即数 width-minus-one 与零位别名，对照由移位/OR 或同宽身份指令组成。三个受支持负例分别改变 amount、旋转方向和位宽。三个 UNKNOWN 检查原始保留编码、候选保留编码和不可达保留编码。

矩阵是宿主持有、版本化且 SHA256 固定的 assembler fixture，不接受工作者 build 参数；真实 NDK 编译后还可由固定 Ghidra 导出并核对每条新字节。原有整数、分支、内存、空域、ABI 观察与不支持场景继续完整执行。

本地分组实际通过独立 ISA 334 项、真实编译 74 项和矩阵 15 项，均零跳过、零失败；去重共 423 项，新增 409 项已包含其中。独立 CLI 的真实 NDK/Ghidra 矩阵为 48/48。42 份 helper ELF 产生 70 个机器比较：26 EXACT、21 DIFFERENT、23 UNKNOWN；另 4 个源码安全审计保持 UNKNOWN。完整输入、实现哈希、实际分母与支持边界见[冻结验收](acceptance/2026-10-18-ror-independent.json)，当前提交的全量远端结果另以 GitHub Checks 为准。

```bash
export AUTO_REVERSE_TEST_NDK_ROOT="$PWD/work/tools/android-ndk-r27c"
export JAVA_HOME="$PWD/work/tools/jdk-21.0.8+9"
export GHIDRA_HOME="$PWD/work/tools/ghidra_11.3.2_PUBLIC"
.venv/bin/pytest -q tests/test_ror_independent.py \
  tests/test_ror_compiler_acceptance.py tests/test_static_acceptance.py
.venv/bin/python scripts/run_static_acceptance.py \
  --ndk-root work/tools/android-ndk-r27c \
  --ghidra-home work/tools/ghidra_11.3.2_PUBLIC --output work/ror-matrix-new
```

所有工具仅在宿主执行。目标 ELF、原库、候选库、目标 harness、模拟器及设备均不执行；原调用 ABI、整库等价、真实 DSH 和完整 M0-S/V1 不因这些局部结果而完成。实际验收数字须来自当前提交的日志和[实施记录](implementation-status.md)。
