# 有限无环条件源码恢复

恢复器可以把受支持的 unsigned AArch64 前向控制流生成有限 C++，再独立审计源码、实际编译，并比较新 ELF 的机器字节。Profile 为 `unsigned-acyclic-register-cfg-1`；旧顺序叶函数的成功源码和映射保持原样。

这项能力不完成 M0-S、原调用 ABI 或整库恢复。源码审计 PASS、编译 PASS、局部机器 EXACT 与当前证据有效是分别检查的义务。

## 输入与范围

- 完整且已知的函数字节范围，最多 1024 字节；0–8 个有可信声明的 unsigned32/64 参数，unsigned32/64 返回。
- 原顺序整数子集，以及原始编码核验的无移位 CMP、EQ/NE CSEL/CSINC 和反条件 CINC/CSET 别名。
- B、CBZ/CBNZ、TBZ/TBNZ 只允许作用域内对齐的严格前向目标。最多 16 个基本块、6 个条件分支、32 条边；全部字节均检查，拒绝不可达材料、后跳、环、出界和不完整出口。
- 所有出口都是受审 RET X30。SP、保留/被调用者保存寄存器、内存、调用、LT/HI、TST、B.cond 和其他 flags 更新不在新增恢复范围。

源码中的原始寄存器使用统一的 unsigned carrier。参数的 32 位声明只提供低 32 位；C++ 初始化一个 64 位 carrier 不会认证原始 Xn 高位。只有实际受审 W/X 写入后才提升可用宽度。每个汇合点取所有结构前驱的初始化、位宽和条件定义交集，不能用最后扫描到的一条路径代替其他路径。

CMP 立即保存布尔条件快照。后续改写比较操作数不能改变已经产生的条件；两条前驱可以来自不同 CMP，但任一前驱缺少定义时不能读取该条件。W 写回和 CSINC 的加一都遵守实际位宽回绕。

## 独立源码安全审计

生成源码使用固定声明、赋值、有限 unsigned 表达式、布尔比较/条件选择、宿主标签及前向跳转。所有声明位于标签之前，入口显式跳转。没有指针、内存、生命周期对象、调用、除法、signed 算术、变量移位、循环或隐式返回。

`source_cfg_safety.py` 从源码独立解析图和数据流，不调用生成器的 CFG 或初始化分析。它检查所有结构分支，包括看似常量的条件与未选中的条件表达式分支。声明类型、C++ 初始化和原始寄存器位宽可用性分别核验。

`audit_generated_leaf` 重新生成完整源码，并另外核验源语法、原始分支 CFG、逐 word 字节及哈希、非重叠源码跨度和固定脚手架。映射保留 `source_line`，新增 `source_line_end` 与 `source_span`；旧聚合恢复入口会同时平移它们。工作者提交的 CFG、映射或“已审计”标志不构成权威。

有限函数报告中的 `complete_cpp_ub_proof=true` 只覆盖报告 `scope` 和 `proof_scope` 指定的这一份生成源码与标量形状；`whole_library_cpp_ub_proof`、`machine_equivalence_verified` 和 `original_calling_abi_verified` 仍为 false。

## 当前工程与最终报告

真实工程编译后，源码安全审计绑定实际 staged source、原始 ELF 的新读取字节/地址、当前标量契约、实际布局材料和审计实现指纹。带类型依赖的源码由审计器内部剥离已经核验的无运行期效果声明，保留原文与材料的绑定；编译使用的完整 guard 仍由实际 TU 构建链核验。

`current`、列表与 FINAL 读取纯重派审计并严格比较完整规范 JSON，不运行编译器、不修改账本。缺少、重复、置换、重算自哈希的错误审计，以及 true/1/1.0 混淆都会使当前材料失效。改变任一新增生成器或 checker 文件会使安全、工程、控制器和最终报告的当前指纹失效；历史报告仍保留。

| 字段 | 含义 |
|---|---|
| `source_safety_current_verified` | 当前审计记录与宿主实际输入匹配；不等于所有义务 PASS |
| `source_safety_summary.passed_source_count` | 选中源码中通过有限审计的数量 |
| `unknown_source_count` | 未证明的选中源码数量；仍需保留范围和原因 |
| `all_selected_source_obligations_passed` | 仅这一批选中源码的有限义务均通过 |
| `whole_library_cpp_ub_proof` | 始终 false；不因局部审计或实际编译提升 |

缺少可信原始标量形状或源码不属于精确生成 profile 时，审计保留 UNKNOWN。这样的工程仍可能合法交付局部 A1 和局部机器证明；源码审计重验成功不会把 UNKNOWN 变为 PASS，完整质量策略保持不变。

## 实际验收与复现

真实固定 NDK 验收包括六类自然 O2 输出、七类独立 raw CFG、反条件/分支臂/常量变异、W 回绕、比较快照和不同 CMP 的路径汇合。源生成与独立审计通过后仍必须编译、匹配实际签名并重新证明新字节，不能用自比较或历史证明代替。Clang 可能把合法源码变为未支持的 LT/TST 等指令，此时保留 UNKNOWN，不使用 asm、volatile 或特殊编译参数迫使验收通过。

```bash
export AUTO_REVERSE_TEST_NDK_ROOT="$PWD/work/tools/android-ndk-r27c"
export AUTO_REVERSE_TEST_CMAKE="$PWD/.venv/bin/cmake"
.venv/bin/pytest -q tests/test_acyclic_recovery.py tests/test_source_cfg_safety.py \
  tests/test_acyclic_adversarial.py tests/test_acyclic_compiler_acceptance.py \
  tests/test_acyclic_project_safety.py tests/test_acyclic_project_adversarial.py
.venv/bin/python scripts/run_layout_dependency_sample.py --conditional \
  --ndk-root work/tools/android-ndk-r27c --output work/acyclic-layout-new
```

固定条件样例通过真实租约交付，冻结原始物理布局及标量契约，恢复两个条件函数，执行两个实际 guarded TU 的候选/工程编译。ZIP 解包到新目录后用固定 CMake 再构建，并对新链接字节重新证明。自动控制器的条件恢复及无工具重复续跑另有实测；原始函数和可执行字节分母、未恢复根与 UNKNOWN 均保留。

所有过程纯静态，不加载或执行原库、候选库、目标 harness、模拟器或设备。模型调用为 0；真实 DSH 验收、任意 C++ 安全、完整类型/调用 ABI、循环、复杂内存和整库闭包继续未完成。当前提交的验收来源与实际 GitHub Checks 见[实施记录](implementation-status.md)。
