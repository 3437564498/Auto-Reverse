# 冻结布局约束与实际编译

本路线把原始布局事务的 `type_ids` 接入候选验证、候选选择、多翻译单元工程、源码 ZIP 和 FINAL。布局声明保持 **A0**；实际编译的局部工程仍按既有规则最高为 **A1**。函数参数和返回值继续限定为 unsigned32/64 标量，结构体声明通过核对并不证明函数使用了该类型，也不证明聚合参数或返回值的调用 ABI。

## 输入与作用域

可信宿主先通过真实 `type_abi` 交付冻结原始布局，再创建同时带 `function_ids` 和 `type_ids` 的源码工作包（recovery/repair/integration/naming）。根 ID 来自原始物理 DWARF 目录；嵌套闭包从原始存储引用派生。每个依赖都必须命中当前有效合同。工作者仍只提交 `schema_version`、`kind`、`symbol`、`source` 四字段，不能选择编译参数、传入宿主断言或自报布局证明。

`contract_read` 向带类型依赖的源码工作者返回 `layout_dependency_contract`，说明有限 profile、指定根和宿主断言权属。宿主排队和执行继续使用既有 `queue-validation` / `validation-worker`、工程集成和最终报告入口，无需开放新的模型工具。公开读取不会启动编译器或安装可选账本。

当前 profile 为 `unsigned-structure-tu-dependencies-v1`：全局或具名命名空间中的普通 `struct`，字段为 unsigned32/64 或显式限定的依赖闭包结构体；允许 cv 限定、字面量 record `alignas` 和固定 packed 属性。类、union、继承、成员函数、模板、匿名成员、位域、数组、别名驱动成员、constexpr 属性和路径/时间上下文宏保留 UNKNOWN。候选源码持有结构定义，宿主公共头继续提供标量函数声明。

自动 `recover-project` 的确定性生成器目前恢复标量叶函数，不自动推断任意函数与结构体的使用关系。本路线中的类型依赖由宿主工作包明确指定。

## 真正进入编译的内容

宿主从当前原库、物理类型闭包和合同派生 authority，绑定当前视图、输入、版本、合同引用及提取器/匹配器/依赖实现指纹。排队、运行、发布、选择、集成和 FINAL 读取都重新核对；同一 revision 下的 CAS 或 current map 被替换也会失效。

固定 Clang 先检查候选物理源码中的声明。宿主据此生成 `sizeof`、字段偏移、确切 C++ 字段类型、平凡性和候选对齐断言，追加到**真正产出 ELF/对象文件的源码**，随后执行实际编译。单独预检通过时 `actual_tu_guard_verified=false`；实际 guarded TU 编译及产物绑定成功后，活动报告才记录已验证。

候选原文、宿主 guard 和实际 compiled source 分别保存哈希、大小与 CAS 引用；不能互换 source 的含义。原始没有声明对齐时，原始对齐继续未知。固定候选自身的对齐用于保证后续编译一致，不补造原始证据。

每个项目 TU 从所选原文重新物化 guard，实际执行 `-c`。跨 TU 对齐物理类型与具名 C++ 类型，并保守要求声明 token、canonical 字段类型、cv、作用域和候选对齐一致。`unsigned long` 与 `unsigned long long` 即使同为 64 位，也不能因此被当作同一 C++ 类型。最终联合 ELF 继续从实际字节重新做局部静态证明。

固定叶函数安全审计只允许移除已独立核验、没有运行时效果的 record 声明及因此真正为空的命名空间，再与原始机器字节重新生成的源码精确对照。其他全局对象、初始化器、函数和语句会保留，不会通过伪造源码范围被隐藏。

## 源码 ZIP 与新目录重建

ZIP 包含实际 guarded `src/*.cpp`、标量公共头、CMake、单独的 guard 文本，以及 `reports/layout-dependencies.json` 中允许公开的类型和字节绑定。私有 authority、回执、会话凭据、账本、原库和对象文件不进入源码 ZIP。

`verify_archived_layouts(root, expected_manifest_sha256=...)` 是纯静态读取：核对实际源码前缀与宿主尾部、公开 shape、哈希和实际 CMake 源文件清单，并从公开标量声明独立重生强制头、与包内 helper 模板及固定 probe 精确对照，并限制本地 include 与 src 搜索目录的实际文件集合，防止宏抹除断言或同名影子头替换。持有可信 manifest 哈希时，应传入该参数核对外部绑定。公开归档不能自行证明原始合同仍为当前，因此始终报告 `original_current_status=UNAVAILABLE_OFFLINE`。

重建验收在新路径用固定 NDK/CMake 编译全部实际源码，检查参与构建的 TU 和新 provenance，再对新链接字节重新证明；旧库的 A1 或 SMT 报告不自动沿用。持有原始输入的可信宿主可以另行核验当前合同和局部机器语义。

## 复现

```bash
.venv/bin/python -m pip install cmake==3.31.6
.venv/bin/python scripts/run_layout_dependency_sample.py \
  --ndk-root work/tools/android-ndk-r27c --output work/layout-dependency-new
```

脚本编译包含原始 DWARF 的固定库，经真实租约、证据读取、Proposal 和 Receipt 冻结布局与两个标量声明，再验证两个带类型依赖的候选、实际多 TU 工程、ZIP 新目录重建、新链接字节证明和 FINAL current。公开摘要为 `layout-dependency-sample.json`。Provider 为离线确定性实现，模型调用数为 0；原始库、候选库、设备和模拟器均不执行。

本批的实际测试结果与来源记录在 [实施状态](implementation-status.md)。完整类型求解、聚合调用 ABI、整库等价和真实 DSH 模型验收继续作为 V1 未完范围。
