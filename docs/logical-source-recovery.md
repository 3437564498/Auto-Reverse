# ANDS/TST 与前向 EQ/NE 的有限源码恢复

`integer-register-logical-cfg-5` 将已经受审的 ANDS logical-immediate、TST 别名与前向 B.EQ/B.NE 接入源码恢复。只有包含这些新原始指令的函数使用 `unsigned-acyclic-register-cfg-2`；既有顺序叶函数与 CFG1 的成功源码、映射保持字节兼容。

这一步恢复有限 unsigned32/64 函数，仍需实际编译、候选签名核验和新机器字节的独立证明。机器模型保持 `arm64-m0-integer-memory-eqne-ands-4`，观察范围、头文件、标量契约和 Schema 未扩大。

## 写回、快照与结构路径

ANDS 为一条原始 word 生成两行：先写实际目的寄存器，再将结果是否为零保存到 `ar_eq`。W 写入清零 X 高半；Rd=Rn 时先读取旧值再写回。TST 只生成一行掩码比较，不产生数据目的寄存器，也不提高原始输入的可用位宽。

B.EQ/B.NE 使用保存的 `ar_eq` 或 `!ar_eq`，随后显式跳向 false 后继。后续改写操作数不会改变已经保存的条件。CMP、ANDS、TST 可以在不同前驱定义条件，但所有结构前驱都必须定义；常量条件不会使另一条路径免检。

32 位原始参数仅认证低 32 位。C++ 的 64 位 carrier 初始化不会认证原 Xn 高位；仅一条前驱执行 W 写入，也不能在汇合后读取未经所有前驱定义的 Xn。有限 profile 保持最多 1024 字节、16 个基本块、6 个条件分支、32 条边，严格前向、对齐、函数内目标及 RET X30 出口。

## 独立检查与当前性

源码 checker 从 C++ 独立重建 CFG、unsigned 类型、全部结构路径的初始化和位宽可用性。CFG2 仅增加精确的 `ar_eq` / `!ar_eq` 分支形式；默认 CFG1 继续拒绝这些新形式。

包装审计器另从实际 word 独立解码掩码、数据目的、TST 别名、分支极性和边，不复用生成器的解码器或 CFG 分析。它核对 ANDS 两行、TST 一行、条件分支两行的完整跨度，拒绝重叠、漏行、吞入标签、错误脚手架或自洽伪造的 mask/Z/目的寄存器。实际 raw 强制对应 profile，不能把新词降称 CFG1 绕过检查。

审计 PASS 表示报告范围内的有限定义行为与来源绑定；`machine_equivalence_verified` 始终为 false。实际语义等价由原始字节和新编译/链接字节的完整机器证明决定。工程和 FINAL 纯读取会重新绑定实际 staged source、原始字节/地址、当前标量契约、布局材料与实现指纹；改变任一生成器或审计器文件会使当前材料失效，历史仍可读。

## 实际编译与工程验收

自然 O2 样例覆盖 mask 选择与 materialize，内部 32 位 cast 不改变其真实公开参数 `(64,64,64) -> 64`。原始 debug ELF 与普通编译逐字节核对，从同一输入提取声明，再恢复、审计、匹配实际 AST 签名、编译生成文本并证明新字节。独立 authored raw 样例覆盖自然编译器未保留的前向 B.EQ/NE，不将其称为自然 Clang 分支。

固定工程样例通过真实租约/回执冻结原始布局和标量契约，恢复两个 logical-flags 函数，真实编译两个含布局断言的 TU。源码 ZIP 在新路径用固定 CMake 重建，对新链接字节重新证明，不复用历史证明。自动控制器另验证完成后的重复续跑不增加事件、任务或工具活动。

```bash
export AUTO_REVERSE_TEST_NDK_ROOT="$PWD/work/tools/android-ndk-r27c"
export AUTO_REVERSE_TEST_CMAKE="$(command -v cmake)"
.venv/bin/pytest -q tests/test_logical_source_*.py
.venv/bin/python scripts/run_layout_dependency_sample.py --logical-flags \
  --ndk-root work/tools/android-ndk-r27c --output work/logical-source-new
```

冻结后的完整本地回归为 **3855 passed、0 skipped、0 failed**（966.09 秒，1 条既有警告），新增 273 项已包含。实际计数、首次旧预期失败过程与输入/工具指纹见[实施记录](implementation-status.md)及[冻结验收](acceptance/2026-10-19-logical-source.json)；远端结果以同一提交的实际 GitHub Checks 为准。

## 仍然未知的范围

在本篇记录的 CFG2 冻结提交中，真实 64 位变量 ROR helper 因 NEG 和变量 LSRV/LSLV 仍为整函数源码 UNKNOWN。后续 CFG3 已单独恢复这些有限形式，详见[变量移位源码恢复](variable-source-recovery.md)。寄存器/移位 ANDS、BC、LT/HI、后跳、循环、调用、内存与通用 C++ 仍未加入。

全部过程只执行宿主工具，不加载或执行原库、候选库、目标 harness、初始化器、设备或模拟器。模型调用数为零；真实 DSH、完整 M0-S/M0-R、完整类型/调用 ABI、整库闭包和 V1 尚未验收，最高交付仍为局部 A1。
