# 有限 CMP 与 EQ/NE 条件选择机器模型

这项能力用于比较真实 AArch64 字节，处理固定 NDK O2 常见的 CMP、CSEL、CINC 和 CSET。机器模型与源码恢复分别验收；有限条件 C++ 生成见[无环源码恢复](acyclic-recovery.md)。本模型不证明完整调用 ABI、全库语义或 M0-S 的全部退出条件。

## 支持的编码

最初 CMP/EQ-NE profile 为 `arm64-m0-integer-memory-eqne-3`；当前 `arm64-m0-integer-memory-eqne-ands-4` 另支持 [ANDS 逻辑立即数与局部 EQ/NE 分支](logical-flags.md)。每条本组指令都从原始 32-bit word 与固定 Capstone 的解码独立交叉核对，不仅按打印出来的 mnemonic 执行。

- CMP：SUBS 的零寄存器目标别名，32/64 位、无移位的 12-bit immediate，或无移位的同宽寄存器。SP/WSP、扩展寄存器、移位 immediate 和保留编码不放行。
- CSEL 与 CSINC：32/64 位，只支持原始条件 EQ/NE。CSINC 在条件为假时对第二个输入按位宽加一，W 写回将 X 的高 32 位清零。
- CINC 与 CSET：受审 CSINC 别名。打印出来的条件与基础编码条件相反，例如 `cinc ...,eq` 的 raw 条件是 NE；必须同时核对条件、源/目标寄存器及别名结构。

LT、HI 等其他条件、AL/NV、BC.cond、后向条件分支、ADDS、任意目标 SUBS、CCMP 和其他 flags 指令继续 UNKNOWN。CBZ/CBNZ、TBZ/TBNZ 和无条件 B 沿用已有模型；新 B.EQ/B.NE 仅限单独受审的局部前向范围。

## 状态与观察边界

每条可行路径各自保存最近一次受审定义产生的 N/Z/C/V。CMP 的减法符号、零值、无借位及有符号溢出按 32/64-bit 公式计算；ANDS-immediate 按逻辑结果定义 N/Z 并清零 C/V。EQ/NE 消费 Z。进入作用域时 flags 未定义；任何可行路径在有效定义之前消费 flags，整个比较保留 UNKNOWN。分支复制状态时 flags 一同复制，普通无 flags 更新的指令保留它们，后续受审定义覆盖它们。

flags 不在函数边界的观察集合中，这条限制在报告里明确记录。原有 X0、SP、X19–X29、RET 目标和全部 modeled memory 观察不变；初始 LR 必须位于两侧代码范围之外，每条实际 RET 仍需证明不会重入。路径/指令预算耗尽、未闭合路径和两侧任何不支持的字节（含不可达字节）都不能产生等价结论。

Capstone 5.0.9 会把 CMP 左操作数误列为写入。仅对已经 raw 核验的本组指令，IR 根据实际编码生成输入/输出；CMP 只写 NZCV，条件选择只读 NZCV。NZCV 明确表示为 `processor_state`、宽度 4，避免冒充整数寄存器。

可信证明读取器同时检查新模型、完整 assumptions、实际字节和工具指纹。绑定对象按规范 JSON 严格比较，布尔值、整数与浮点数不能互相冒充；报告与证明、范围假设、预算、原始函数及编译绑定必须一致。移除路径 flags 定义限制或修改边界观察，即使重算报告部分哈希，也不能成为当前可选证明。

升级改变模型与实现指纹。旧证明保留为历史，只有用当前字节和当前模型重新验证后，才能恢复为当前有效证明。

## 验证方法

新增测试使用完整 32/64 位域的独立数学公式、原始 ISA 编码、无 flags 的 EOR/CBZ 参考程序和真实固定 NDK 编译结果交叉检查。既有寄存器、内存、返回和预算负例继续执行。反转条件或常量需要给出 DIFFERENT；缺 CMP、LT 和没有合法栈区域契约的 O0 输出保持 UNKNOWN。

本条件模型批次曾向固定静态矩阵新增 9 个场景，形成 36 个：五个条件选择/别名与无 flags 参考的正例、两个反条件负例、缺 CMP 和 LT 两个未知场景。后续 [ROR 独立验收](ror-acceptance.md) 扩展至 48 个，[ANDS 与分支增量](logical-flags.md) 再扩展至 60 个，原有场景全部保留。原始与候选汇编只作为版本化宿主 fixture，SHA256 固定；不接受工作者编译参数，不加载或执行产物。

```bash
export AUTO_REVERSE_TEST_NDK_ROOT="$PWD/work/tools/android-ndk-r27c"
.venv/bin/pytest -q tests/test_eqne_conditionals.py \
  tests/test_eqne_conditionals_adversarial.py tests/test_eqne_compiler_acceptance.py \
  tests/test_eqne_proof_boundary.py
export JAVA_HOME="$PWD/work/tools/jdk-21.0.8+9"
.venv/bin/python scripts/run_static_acceptance.py \
  --ndk-root work/tools/android-ndk-r27c --ghidra-home work/tools/ghidra_11.3.2_PUBLIC \
  --output work/eqne-matrix-new
```

全部检查只运行编译器、静态解析器和 Solver。真实 DSH 模型验收仍未完成；有限无环条件源码生成与独立 CFG 定义行为审计见[单独实现与边界](acyclic-recovery.md)，不由本机器模型的 EXACT 自动成立。
