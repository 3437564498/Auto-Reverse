# M0-S 首版静态可信性原型退出核对

更新：2026-10-19（Asia/Singapore）。本记录依据 [V1 第 33 节](android-arm64-so-cpp-recovery-V1.md#33-里程碑与退出条件)，核对已执行的有限原型证据。退出判定依据实现 `c4591f9`，已由 [PR #14](https://github.com/3437564498/Auto-Reverse/pull/14) 合并进 `main` 的 `6239c2a`。退出核对本身只读取代码、实际 CI 产物和既有报告，没有重新运行编译器、Solver 或全量测试；本批另外执行了下文单独列出的 byte helper 补证，不把它增设为历史原型退出前置。所有工作均未运行原库、候选库、目标 harness、初始化器、模拟器或设备。

**结论：第 33 节所列的有限静态可信性原型退出项已有实际证据满足。**这个结论绑定下述微型样本、机器观察、前提和 helper 范围；它不证明当前能力表每个操作的全部编码、全部随包 helper 或任意程序都已独立验收。未发现需要先新增内存上下文账本、支持整个 ISA 或证明完整调用 ABI 才能修复的首版原型阻塞。

完整 V1、真实 DSH/M0-R、通用类型与调用 ABI、整库恢复继续未完成。本记录保留具体证据缺项，不能被引用为整个处理器模型或全部 helpers 的验收证书。

范围化机器可读判定见 [M0-S 原型核对记录](acceptance/2026-10-19-m0-s-prototype.json)。其 decision 基于已完成的 `c4591f9` 证据，新增补证的结果另列。

## 判定依据和冻结范围

V1 第 33 节的原文为：

> 交付：Android微型样本、自动导入、结构化Raw IR、opcode能力表、helpers与最小比较。
>
> 退出条件：精确整数/分支/受控内存正反样本正确分类；独占/未知语义不误通过；空域/越界/ABI错误被阻断。

这里的原型证明指定精确子集能够正确分类，且范围外能力不会误通过。原文没有要求完成全 ISA、通用循环、完整 AAPCS64 类型恢复或整库工程。V1 也明确允许 M0-S 与 M0-R 独立推进。

本次证据使用当前机器模型 `arm64-m0-integer-memory-eqne-ands-4`：AArch64 little-endian、明确支持的 32/64 位整数、局部分支及固定有效区域中的普通字节内存。完整能力与编码限制由 [capabilities.py](../src/auto_reverse/capabilities.py) 发布，不能仅按助记符或 Ghidra 提升结果赋予精确支持。

默认机器观察为完整 X0、SP、X19–X29、RET 的目的地址和全部 modeled memory。初始 X30 必须位于两侧代码范围外；每次实际 RET 还需证明其目标不回到任一代码范围。NZCV 只供受支持的函数内条件使用，不作为返回边界观察；外部调用及返回后续行为不在本原型范围内。预算耗尽、缺少内存区域或未闭合路径不给精确等价。

源码增量的 `integer-register-variable-cfg-6` 与 `unsigned-acyclic-register-cfg-3` 是另外的有限恢复/安全证据，不改变上述机器模型和观察范围。随包头文件版本为 `arm64-m0-unsigned-bits-1`；其全部函数的独立验收覆盖须逐项说明，不能因头文件曾被包含就全部记为通过。

## 实际远端执行与可复核产物

- [固定工具 CI 39200087245](https://github.com/3437564498/Auto-Reverse/actions/runs/39200087245)，[任务 117891056084](https://github.com/3437564498/Auto-Reverse/actions/runs/39200087245/job/117891056084)：**4260 passed、0 skipped、0 failed**，1132.50 秒，1 条既有警告。该数字对应已合并的 `c4591f9`，不包含本批新增的 35 项 byte helper 测试。
- [产物 12164131415](https://github.com/3437564498/Auto-Reverse/actions/runs/39200087245/artifacts/12164131415)：下载 ZIP 为 441751 字节、33 个文件，SHA-256 为 `c05598a008d1088ba98a388b4bebf33980d10925aba419c51624e97cbe354b21`。
- ZIP 内 `static-acceptance/static-acceptance-report.json` 的 SHA-256 为 `0cd61214b30304d586fc88360a4ae52fbc2390e93f467d748b6750bf36721e7d`；固定 [manifest](../examples/static-matrix/manifest.json) 的 SHA-256 为 `bcf1e4413536da7e16587e21d9da047db95b558b549b81f92475c6fa67adff37`。
- 实际矩阵为 **60/60**：22 EXACT、16 DIFFERENT、20 UNKNOWN、2 INVALID_PRECONDITION，全部符合冻结预期；原/候选完整 fixture 符号集合匹配，分类字节分别为 616/688。UNKNOWN 与 INVALID 是预定负向门禁的正确结果，没有算作精确正例。

固定工具为 NDK r27c / `27.2.12479018`、Ghidra `11.3.2`、Temurin `21.0.8+9`，锁定来源见 [static.lock.json](../toolchains/static.lock.json)。本产物记录 Capstone package `5.0.9`、binding `5.0.7`；两者都作为工具身份保存，不混用版本字段。

| ZIP 中证据 | 实际哈希/状态 | 能说明什么 |
|---|---|---|
| `static-acceptance/original/libstatic_matrix.so` | `f05b9e968f70b54c25a73386f5b34f127440712a24bf008e288254ff68ae86f0` | 固定原始汇编实际生成的 Android ELF；不是伪 IR |
| `static-acceptance/candidate/libstatic_matrix.so` | `9de54b9f86f4a7b0f5b443a3ab3918c5b30ee05c79d4514e8b3d252e1dacd8c7` | 固定正反候选实际生成的 Android ELF |
| `static-acceptance/ghidra-original/raw-ir.json` | 957827 字节；`221748d135cef1197c4754f99e7ddb0abe2fc2d14e181236deadf4777a9b6dd6` | 原字节与结构化 Raw IR、opcode capability 的来源绑定 |
| `static-acceptance/ghidra-candidate/raw-ir.json` | 929934 字节；`24e8b49f45853daea50ee2959f15cf73123cced395b9f13daae51e19bf9db1f8` | 候选侧同样保留来源；不能仅检查原始一侧 |
| 两侧 `analysis-manifest.json` | 实际 `exported`、return code 0、进程组和临时工程清理确认 | 真实自动导入和导出；没有运行库或 resolver |
| `variable-source-acceptance/layout-dependency-sample.json` | SHA-256 `3aa84f895af5fc2c2e906ae5048b8bad0218113d4d0a2f10b9beaee885b81e1f`；sample PASS | 两份实际 CFG3 源码、独立 current 审计、guarded TU 与 ZIP 新链接字节的补充工程证据 |

Ghidra 报告中的 `function_discovery_complete=false` 和 `processor_semantics_complete=false` 是全局发现/处理器语义边界。当前最小 verifier 不把 P-code 当精确语义公式；[runner](../scripts/run_static_acceptance.py) 对原始 word 和 P-code 来源交叉绑定，再由独立版本化机器模型证明。38 个 EXACT/DIFFERENT 场景的两侧实际 word 都已 source-linked；有损或不支持的提升保留 UNKNOWN，不因此要求实现整个处理器后才能退出原型。

## 第 33 节逐项退出映射

| 原文义务 | 现有实际结果与独立依据 | 判定及边界 |
|---|---|---|
| Android 微型样本、自动导入 | 固定 NDK 真实构建两侧 ELF；manifest/source SHA 与完整 fixture inventory 核验；实际 Ghidra 自动导入并产出上述 Raw IR | 满足有限固定分母；不是全库函数发现完成 |
| 结构化 Raw IR、opcode 能力表 | 每个 word 绑定地址/字节/源指令及原 opcode capability；LDXR 的有损 LOAD 或 PAC 空 P-code 不继承普通 load/NOP 的精确支持 | 满足来源和 fail-closed 分离；P-code 不自行产生等价证明 |
| helpers 与最小比较 | 实际打包头文件、固定编译参数；add 最小 helper 比较、ROR/W 零扩展的独立位关系和实际编译；固定 LSL helper 的真实原字节及 CFG3 独立逐位规则 | 满足已明确 helper 的最小比较；全部 helper 的独立证据缺项见下一节 |
| 精确整数正反样本 | `integer64_equal/changed`、`integer32_equal/changed` 分别 EXACT/DIFFERENT；独立 unsigned 模运算/W 零扩展边界、真实编译与 SAT witness | 满足首版正反样本；300 个常量差异仅是同族负例，不称 300 个指令族 |
| 精确分支正反样本 | `branch_equal/changed`；CMP/EQNE、ANDS/TST 与前向分支正反矩阵；独立条件数学、NZCV bit 规则及原始编码核验 | 满足支持条件/路径范围；LT/BC/后向条件分支不据此加入 |
| 受控内存正反样本 | `memory64_equal/changed`、`memory32_equal/changed`、`signed_load_equal/changed` 各为 EXACT/DIFFERENT；独立 alias/read-after-write、byte truncation、signed extension 和 store-effect 规则 | 满足 host-owned 固定 normal-memory 域；对完整 modeled memory 比较，未只观察返回值 |
| 独占/未知不误通过 | `exclusive_original`、`exclusive_candidate`、`pac`、`dmb`、`unknown_opcode`、`indirect_branch` 实际均 UNKNOWN；不可达不支持 word 也保留能力检查 | 满足。UNKNOWN 是正确负向结果，支持这些语义不是首版前置 |
| 空域被阻断 | `empty_domain`、`contradictory_domain` 实际 INVALID_PRECONDITION；记录前提不满足且不运行等价差异求解 | 满足，不用 UNSAT 空域冒充等价 |
| 越界/权限错误被阻断 | `memory_oob`、`memory_missing_region`、`memory_readonly_write` 实际 UNKNOWN；独立 code/data overlap、区域大小、访问宽度等检查 | 满足已声明 normal-memory 模型；不安全/未证明的访问未计为精确反例或通过 |
| 首版 ABI 错误被阻断 | `callee_saved_changed`、`stack_changed` 实际 DIFFERENT；结构 ABI suite 拒错 ELF profile、导出/可见性/依赖/版本；未知 original calling ABI 不提升 PASS | 满足已声明机器/结构义务。完整调用 ABI、FP/聚合/栈传参仍未知 |

以下已有 SAT witness 可以直接从产物理解差异，无需执行目标或重新求解：

- `memory64_changed` 的原字节为 `200000f9200040f9c0035fd6`，候选仅 `c0035fd6`。见证令 X0=0、X1=`0x80000000`、该区域偏移 6 原值为 `0x02`。原程序的 STR 将该字节写为 0，候选不写；两侧 X0 相同仍报告 DIFFERENT。这说明内存写入没有被返回值相等掩盖。
- `signed_load_changed` 令读取字节为 `0x80`。产物观察原 X0=`0x00000000ffffff80`，候选为 `0x80`，区分 W signed-byte load 与 unsigned-byte load。
- `callee_saved_changed` 在 X0=0、初始 X19 全 1 时，原 X19 保留全 1，候选改为 0；`stack_changed` 在初始 SP=0 时，候选 SP 变为 `0xfffffffffffffff0`。两者 X0 相等仍 DIFFERENT。

## 独立规则与 helper 覆盖，避免把“已实现”当“全验收”

下面的测试在该次实际完整 CI 中执行。其规则来源可从源码检查；本记录没有再次求解这些公式。

| 支持范围 | 独立依据 | 证据强度与缺项 |
|---|---|---|
| unsigned UBFM/UBFX/UBFIZ 及相关别名 | [test_unsigned_bitfield.py](../tests/test_unsigned_bitfield.py) 用直接 bit slices/Concat 对照生产 shift/mask；遍历合法字段的 decoder alias，拒保留值和错 metadata | 有独立符号 bit 关系、raw 字段与真实编译链；不赋予 signed/preserving bitfield 支持 |
| CMP/EQNE CSEL/CSINC/CINC/CSET | [test_eqne_conditionals_adversarial.py](../tests/test_eqne_conditionals_adversarial.py) 直接构造比较/选择数学，检查全输入寄存器、帧和原条件；不调用生产 conditional decoder 作 oracle | 覆盖明确 EQ/NE 族；不是全 NZCV/全部 condition |
| ANDS immediate/TST 与前向 EQNE | [test_logical_flags_adversarial.py](../tests/test_logical_flags_adversarial.py) 独立 circular-run mask、逐 bit NZCV/帧规则与 raw branch target；16384 个字段组合 | raw 合法性/结果/flags/分支角色有独立证据；寄存器 ANDS、BC/其他条件仍未知 |
| RORV/同源 EXTR-ROR W/X | [test_ror_independent.py](../tests/test_ror_independent.py) 逐 bit 置换/布尔 mux；[真实 helper 编译](../tests/test_ror_compiler_acceptance.py) 使用独立 raw reference | 完整 amount/source 符号输入、W 高半/ZR/帧，错误方向/amount/位宽有 SAT；旧模型的 X-variable helper UNKNOWN 没有被改写成通过，后续按新字节另验 |
| CFG3 NEG/LSLV/LSRV/RORV 的生成表达 | [test_variable_source_adversarial.py](../tests/test_variable_source_adversarial.py) ripple NEG 与逐位选择/mux；[编译验收](../tests/test_variable_source_compiler_acceptance.py) 把实际新字节与原字节重比 | 该有限生成语法及实际原始 helper 独立通过；不等于包装头文件每个模板实例都通过 |
| 普通整数、移位、除法和内存机器边界 | [test_semantic_review.py](../tests/test_semantic_review.py)、[test_semantics.py](../tests/test_semantics.py) 独立 ISA 边界、alias/partial overwrite、signed extension、SDIV/UDIV 除零与溢出；60-case 实际矩阵 | 已有具体独立规则及正反样本；没有一份证明覆盖每个已支持操作的全部编码及全输入，与全 ISA 认证区分 |

随包 helper 的覆盖另列，不能以相关 opcode 测试替代“该 helper 实际编译过且与独立规范比较”：

| 头文件函数 | 现有可指认事实 | 不应声称的结论 |
|---|---|---|
| `add` | `examples/ndk` 实际最小 helper 源码和 build-gate 正反比较；unsigned 模运算 source 审阅与机器 ADD 规则 | 最小样例不等于 W/X 任意两个参数的全部 helper 编译配置已验收 |
| `ror`、`write_w` | 独立置换/W 清零规则、真实打包头文件、W/X/立即量/变量及运行库配置的新 ELF 比较；CFG3 再验实际七 word X helper | 不把普通 uint32 identity 的 RET 与完整 W 清零混为一谈；不能缩窄输入隐藏差异 |
| `lsl` | 新真实工程 `shift_word` 调用随包 X helper；normal O2/debug 字节一致，实际 raw LSLV，恢复后重新编译与完整观察证明；CFG3 shift 独立 bit oracle | 这不是所有 W/X `lsl` 模板及 `lsr/asr` helper 的专用验收 |
| `sub`、`mul`、`lsr` | 头文件中存在实现；相关机器 opcode/普通生成表达有测试；`sub` 还供 `sdiv_bits` 使用 | 仓库没有可定位的这些 helper 独立真实编译/规范全域链，不能因相近 opcode 通过就填上 |
| `asr`、`udiv`、`sdiv_bits` | 头文件有少量直接 static_assert；机器边界测试检查移位模量、除零、INT_MIN/-1 等；unsigned 实现避免相应 signed UB | 仍缺这些实际 helper 自身的专用编译及独立规范输入覆盖，不能把少量 static_assert 称为全域验收 |
| `load_le`、`store_le` | 历史 header 仅有 roundtrip；本批已新增独立固定 byte 序列的 load/per-byte store 校准、真实 W/X wrappers 与手写 LDR/STR 比较，以及实际编译变异和边界 UNKNOWN，专项 35 项通过 | 本批补上具体端序/字节链证据；固定有效对象及 normal-memory fixture 是明确前提，不证明任意指针、对象 lifetime/provenance、调用 ABI 或通用内存 C++ UB |

上述尚缺的项是**具体的证据覆盖缺项，没有观察到相应 helper 的实现错误**；`load_le/store_le` 的本批补证与其余未覆盖项分开记录。第 33 节要求 helpers 与最小比较，已有明确有限 helper 的实际编译和独立比较满足该最小交付；原文没有要求整个 header 的全部模板/配置全域证明。若后续要宣称“全部随包 helpers 已独立验收”，剩余缺项仍必须补齐，不能用本记录免除。

## 本批 byte helper 专项补证

新增 [test_byte_helper_acceptance.py](../tests/test_byte_helper_acceptance.py) 的 SHA-256 为 `7074444105e14863896fe9e5ee1ffddd49f393d7f5f54f115f9025ef619a4b30`。固定 NDK r27c 的实际专项为 **35 passed、0 skipped、0 failed，13.72 秒**。未配置 NDK 的独立分支为 35 项明确 skip，不能算真实编译验收。本记录写入时，新提交完整 CI 尚待执行；旧远端 4260 项结果不能冒充新增后 4295 项的完整远端结果。

本次实际生成 17 份新 ELF，并得到 6 次有意设置错误期望的 constexpr 编译失败；69 次工具命令均确认清理。独立 constexpr 向量共 106 组：32 位 37 组、64 位 69 组，包含每一个 onehot 位。每组分别以固定 scalar literal 验证 load、逐字节 literal 验证 store，不以 `load_le(store_le(value))` 给出任一方的期望值，因此补上了“双方共同反端序仍可能 roundtrip 正确”的历史盲点。

机器比较共 25 次，状态分母明确分为：

- **8 EXACT**：W/X load/store 四个实际 O2 wrapper，各在 `c++_shared`、`c++_static` 下，与测试独立持有的 LDR/STR 原始字节比较。
- **4 DIFFERENT**：W/X load 后右移 1 位，以及 W/X store 写入值加 1 的真实编译变异；均在受支持模型内产生 SAT witness。
- **13 UNKNOWN**：12 个缺区域、越界或错误权限场景，另有一个正常 O2 将 32 位 load 后右移 8 位优化成未支持 `LDURH` 的场景。后者保留真实编译形状和 UNKNOWN，没有将其冒充精确反例，也未扩大 opcode 范围。

8 个正例的自然编译字节与独立持有的原始 reference 恰好相同，验证的是实际构建、操作数角色和证明上下文绑定；独立端序证据来自上述 literal/逐字节 constexpr 校准，不应将它们称作另一套独立 LDR/STR 语义定理。

这些机器比较的地址前提为 X0=`0x40000000`，共享 64 字节普通有效内存区域。区域中的初始字节及 store 数据保持任意，默认完整 X0、SP、X19–X29、RET 与全部 modeled memory 观察不变。这里只证明固定地址 fixture 中的机器行为；不声称覆盖全部运行时地址、建立任意 caller 对象或证明指针 provenance。有限 helper 的定义行为说明以实际存活且可访问的固定大小 byte array 为前提，移位分别仅为 0/8/16/24 或 0/8/16/24/32/40/48/56；不是任意 C++ 内存源码 UB 或原调用 ABI 证明。

本地正式 manifest 为 `work/byte-helper-publish-final/byte-helper-real-compiler0/byte-helper-acceptance.json`，SHA-256 `c5f4415b5eeedaf30d8449d3b01e250ffd982967a3730e8d6039f0b9a78d02ca`；实际日志为 `work/byte-helper-publish-final.log`。首次开发尝试为 27 passed、7 failed：6 处是测试错误解释结构化 stderr，另 1 处是将自然 `LDURH` 形状错误预期为 DIFFERENT。初始记录保留，修正测试分类并另外使用受支持的右移 1 位变异后专项完整通过；生产代码及头文件始终未改。

[专项冻结记录](acceptance/2026-10-19-byte-helpers.json)保存最终输入、日志及首次尝试；固定 CI 通过 `AUTO_REVERSE_BYTE_HELPER_REPORT` 另存同一份实际报告，只上传此公开 fixture JSON。导出验证已确认默认与公开副本逐字节相同（838106 字节）；不上传临时目录、ELF 或私有 Job 状态。

这一单元补足两项具体 helper 的证据，不回溯增设第 33 节硬退出条件，也不补齐 `asr/udiv/sdiv_bits` 等其他 helper 的全部独立验收。后续按实际使用范围补剩余独立规范和编译绑定；正常编译产生范围外形式时继续 UNKNOWN，不使用 asm、volatile 或特别参数强行通过。

## 范围外 UNKNOWN 与后续里程碑

浮点/NEON、独占/原子/屏障、PAC/BTI/MTE、SVE/SME、未闭合循环、未解析间接控制流、外部调用、异常、TLS/MMIO、复杂指针/alias 等未建模时维持 UNKNOWN。对首版 M0-S，它们的正确拒绝是可信性证据，支持这些能力本身不是退出前置。

原型中的 ABI 负向门禁覆盖既定 SP/保存寄存器/RET 观察和有限结构检查。完整 original calling ABI、栈参数、FP/聚合/HFA/向量、this/Thunk、调用者对象/指针有效性不因此获证；没有把 `original_calling_abi_verified` 改为 true。

宿主冻结的内存上下文贯穿候选→选择→工程→ZIP/current 是后续 **M1 持久验证链路**的真实缺口：现有 `load_word` 提案仍会因缺独立区域/前提而 UNKNOWN。但低层 verifier 已从可信 fixture 取得区域并完成本节正反/越界分类，故这个生产上下文服务不是第 33 节新的硬退出条件。其开发应保留显式环境假设，不能把 worker finding 或 PT_LOAD 权限冒充调用者有效指针、C++ lifetime 或完整 calling ABI 证明。

## 历史 false 字段与对外措辞

`scripts/run_static_acceptance.py`、冻结 manifest 和历史产物中的 `full_m0_s_exit_satisfied=false` 是原先 runner 的固定保守声明：单个静态矩阵从不自行代表全部 milestone 审核。它没有逐项聚合退出条件，其 `scope_gaps` 还列有全处理器语义、整库闭包、原始类型/ABI 等更广边界。因此该字段本身既不是一项具体失败的证据，也不能通过简单删除/改成 true 来宣布退出。

本记录补充的是**第 33 节有限原型退出的跨证据核对**；旧 JSON 的字节、历史结论和软件行为保持不变。引用本记录时应写：

> M0-S 首版静态可信性原型在已冻结微型样本、明确机器观察和有限 helper 范围内完成退出核对；完整模型、全部 helper、调用 ABI、真实 DSH/M0-R 和整库 V1 仍有未验收范围。

不能写“完整 V1 已完成”“全 ARM64 精确验证完成”“所有 helper/UB/调用 ABI 已证明”。后续若建设机器可读退出摘要，应使用独立版本和明确 scope 关联原 artifact、规则与核对记录；不重写旧报告或让读取接口触发编译、求解和账本写入。

本批与 [实施状态](implementation-status.md) 分开记录历史退出依据和新增 helper 补证；下一动作是核对新提交包含新增 35 项的实际完整 CI，而不是用旧 4260 项代替。退出核对结论不依赖重新运行同一历史范围。随后可推进有界的 M1 受控内存上下文开发；真实 DSH/M0-R、完整类型/调用 ABI、隐藏函数/调用摘要、全局/TLS/初始化和整库入口闭包继续单独跟踪。
