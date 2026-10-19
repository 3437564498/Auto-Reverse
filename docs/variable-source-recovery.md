# NEG 与有界变量移位源码恢复

`integer-register-variable-cfg-6` 将精确的无移位 NEG，以及 W/X 寄存器 LSLV、LSRV、RORV 接入有限源码恢复。只有包含这些新原始 word 的函数使用 `unsigned-acyclic-register-cfg-3`；旧叶函数、CFG1 和 CFG2 的成功源码与映射保持字节兼容。

本批能恢复固定头文件实际编译出的七指令 64 位变量 ROR helper，以及另行验证的直接 RORV 形式。两者分别经过源码恢复、独立安全/current 审计、实际 AST 签名、固定 NDK 编译和新字节的完整机器证明。机器模型保持 `arm64-m0-integer-memory-eqne-ands-4`，头文件、观察范围、标量契约和 Schema 未扩大。

## 每次移位都重新证明边界

NEG 仅接受 S=0、Rn=ZR、LSL#0 的 SUB 别名，生成二元 unsigned `0U/0ULL - value`，不使用 signed unary minus。W 结果先按 32 位回绕，再清零 X 高半。

LSLV/LSRV 在每个 RHS 内重新施加 `amount & 31U/63ULL`。即使先前 ANDS 已掩码，后来的 NEG 也可能把 1 变成 `0xffffffff`，不能依赖旧范围直接移位。W 数据在移位前显式转换为 unsigned int；仅在移位后截断不能补救 C++ 的越界移位。

RORV 使用两次各自受界的 unsigned shift 和 OR。反向位移为 `(0U/0ULL - masked_amount) & mask`，最后一次 mask 不可省略；amount=0 时两次移位都为零，不产生 shift-by-width。

源、amount、目的可以别名，所有 RHS 先读取该 word 的旧值，再更新目的。ZR 是宽度正确的字面零，不生成 `ar_x31`；目的仍限实际 X/W0..17。新操作不更新条件快照，保留 CMP/ANDS/TST 已捕获的 `ar_eq`。

## 独立审计与原始高位

独立源码 checker 只在 CFG3 中接受表达式局部能够证明上界小于左操作数提升后位宽的变量移位。unsigned literal、cast、AND 与保守算术界用于证明，不跨赋值传播范围，也不利用常量分支免检另一结构路径。CFG1/CFG2 保持原来的 constant-only shift 规则。

C++ 的范围证明不能覆盖原始寄存器高位义务。首版对数据与 amount 均保守要求实际指令位宽已定义；uint32 formal 不自动提供 X 高半。真 W 写入才定义整个 X carrier，汇合仍取全部结构前驱的初始化、位宽和条件定义交集。

raw 包装审计器独立核验固定编码位、操作、W/X、Rd/Rn/Rm、ZR、精确掩码/旋转补数、单行 word span 和 profile 优先级。它不调用生成器或机器模型的 decoder；保留位、NEGS、shifted NEG、ASRV、错角色、错方向、profile 降称及自洽伪造均拒绝。定义良好但错误的小 mask 可以通过 source-only 安全检查，仍须被原始来源绑定和新字节机器证明分别拒绝。

审计 PASS 只覆盖报告指定的有限源码定义行为与来源，`machine_equivalence_verified=false`。最终字节等价由独立机器证明决定；source/kernel/typed shape/layout 材料变化使当前证据失效，历史仍保留，public current 不编译、求解或写账本。

## 真实工程与复现

固定工程样例从同一 debug ELF 核验两个真实 `(64,64)->64` 声明，并逐字节比较 normal O2 与 debug 函数。它经真实租约/回执冻结标量和布局，恢复 ROR/LSL 两函数，编译两个实际 guarded TU。ZIP 在新路径用固定 CMake 重建后，重新提取新链接字节证明；自动控制器完成后续跑不增加任务、事件或工具活动。

```bash
export AUTO_REVERSE_TEST_NDK_ROOT="$PWD/work/tools/android-ndk-r27c"
export AUTO_REVERSE_TEST_CMAKE="$(command -v cmake)"
.venv/bin/pytest -q tests/test_variable_source_*.py
.venv/bin/python scripts/run_layout_dependency_sample.py --variable-shifts \
  --ndk-root work/tools/android-ndk-r27c --output work/variable-source-new
```

冻结后的完整本地回归为 **4260 passed、0 skipped、0 failed**（1056.17秒，1条既有警告），本次新增405项已包含。测试数字、初轮失败与工具/输入指纹见[实施记录](implementation-status.md)及[冻结验收](acceptance/2026-10-19-variable-source.json)；完整远端结果须核对当前提交的实际 GitHub Checks。此前 CFG2 快照中的 helper SOURCE UNKNOWN 是当时的正确边界，不作为本批结果。

ASRV、NEGS、shifted NEG、一般 ZR 算术、变量移位的通用调用、循环、调用与内存恢复仍未加入。原库与候选库、初始化器、目标 harness、设备和模拟器均不执行；模型调用为零。最高交付仍为局部 A1，真实 DSH、完整 M0-S/M0-R、类型/调用 ABI、整库闭包及完整 V1 尚未验收。
