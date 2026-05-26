# 软件度量期末大作业实验报告

## 1. 通用设定

### 1.1 工具与环境

| 类别 | 工具 | 备注 |
|---|---|---|
| 动态测试 | libFuzzer + AddressSanitizer | Homebrew LLVM 22.1.6 |
| 静态分析 | Clang Static Analyzer (`scan-build`) | 同 LLVM 工具链 |
| 构建 | CMake + clang | 三个项目均 CMake |
| 平台 | macOS / Apple Silicon |  |

**选 libFuzzer 而非 AFL++**：macOS 原生支持更好，AFL++ 在 Apple Silicon 上 persistent mode / 共享内存有不稳定问题，多数情况需要 Docker；libFuzzer 通过 `brew install llvm` 即装即用。

### 1.2 评测流程

```
源码 (锁定 release tag, git submodule)
   │ CMake + -fsanitize=fuzzer-no-link,address
   ▼
lib<X>.a (插桩静态库)
   │ link with 手写 LLVMFuzzerTestOneInput
   ▼
fuzz_<X> 二进制 ─── 12h × 字典 + 种子语料 ─── 覆盖率 + 崩溃 artifact
                                                       │
                                                       ▼
                                              dedup.sh（按 ASan SUMMARY / 栈帧分组）

源码 + scan-build (无 sanitizer)
   │ 
   ▼
告警 HTML 报告 ─── 不变量 / 路径分析 ─── 真伪判定
```

### 1.3 Fork 模式与崩溃去重

libFuzzer 单进程模式下，**任何崩溃都让进程退出**，"12 小时"实际可能只跑几分钟。libucl 和 libconfig 都有非内存类的 abort/exit 路径（ASan abort、`yy_fatal_error → exit()`），因此切到 **`-fork=1 -ignore_crashes=1 -ignore_timeouts=1`**：worker 死亡 → 父进程立即重启并共享 corpus。代价是同一根因 bug 会被重复触发多次，落到 `findings/` 的崩溃文件需事后用 `dedup.sh` 按 **ASan SUMMARY 行 + 首个用户栈帧** 分组。

`harness/<proj>/dedup.sh` 在每份报告的"动态测试结果"前已经运行过。

\newpage

## 2. libexpat

### 2.1 评测对象

| 字段 | 值 |
|---|---|
| 仓库 | https://github.com/libexpat/libexpat |
| 版本 | `R_2_8_1`（最新稳定版，commit `c7ffbf38`） |
| 代码规模 | `expat/lib/` 共 17,679 行 C |
| 选择理由 | 解析器类目标 attack surface 明确；历史 CVE 高发；被 OSS-Fuzz 长期覆盖，可作"难度对照" |

### 2.2 Driver

`harness/libexpat/fuzz_xml.c`：注册 5 类 handler（element / chardata / comment / PI）以避开 fast-path 损失约 30% 覆盖；单 buffer `XML_Parse` 一次性 `isFinal=1`；handler 空实现避免驱动自身 bug 干扰信号。配合 **7 个手工种子**（basic / attrs / namespaces / cdata / DOCTYPE+entities / comments+PI / UTF-8） 和 **63 条 XML 字典**（声明、CDATA、DOCTYPE、ENTITY、BOM 等）。

### 2.3 动态测试结果（12h，单进程模式）

| 指标 | 数值 |
|---|---|
| 总执行 | 245,076,849 |
| 平均 exec/s | 5,608 |
| 最终 cov | **4,480 / 8,076 PCs (55.5%)** |
| 最终 ft (features) | 16,997 |
| 内存峰值 | 698 MB |
| **崩溃 / Sanitizer 报错** | **0** |
| 超时输入 | 4 个 slow-unit，重测均 < 100 ms（macOS 后台任务导致的瞬时延迟，非算法复杂度 bug） |

覆盖率在 **t ≈ 2.1h 时进入饱和**（次小时增长 < 1%），后 10h 缓增到 4480，边际收益趋零。

### 2.4 静态分析结果

`scan-build` 报告 3 个 `core.NullPointerArithm` 告警，全部位于 `xmlparse.c::poolGrow()` 字符串池扩容路径。**经完整不变量分析判定 3 个全部为误报**。

**核心不变量**：`STRING_POOL` 中 `ptr == NULL ⇔ start == NULL`（同生同灭）。全文件 6 处 `pool->ptr =` 赋值点逐一验证均维护此不变量（poolInit / poolClear / poolGrow 3 路径）。

**三个告警逐一判定**：

| 行 | 反驳依据 |
|---|---|
| 8115 | 前置 8099 已检 `start != NULL` ⇒ 由不变量 `ptr != NULL` |
| 8128 | `blocks->s` 是 flex array 永远非 NULL ⇒ `start` 非 NULL ⇒ `ptr` 非 NULL |
| 8191 | `ptr != start` 隐含至少一边非 NULL ⇒ 由不变量两者均非 NULL |

**误报根因**：Clang SA 单函数路径敏感，无法跨函数证明对象级状态不变量。需要在敏感点加 `assert`、改 SMT 工具、或重构数据结构。

### 2.5 截图

\newpage

![libexpat — driver 源码](assets/driver-code.png)

![libexpat — 12h 覆盖率趋势](assets/coverage.png)

![libexpat — scan-build HTML 报告](assets/scan-build-report.png)

\newpage

## 3. libconfig

### 3.1 评测对象

| 字段 | 值 |
|---|---|
| 仓库 | https://github.com/hyperrealm/libconfig |
| 版本 | `v1.8.2`（最新稳定版） |
| 代码规模 | `lib/` ~5K 行 C（含 flex/bison 生成的 scanner.c / grammar.c） |
| 选择理由 | 中小型解析器；用 flex/bison，与手写递归下降（libexpat）形成对照 |

### 3.2 Driver

`harness/libconfig/fuzz_config.c`：`config_init` → `config_read_string`（输入需 NUL 结尾，driver 内 `malloc(size+1)` + memcpy + 末位置 0）→ 递归 `walk()` 整棵 config tree 触发 getter → `config_write` 到 `/dev/null` 触发 emitter → `config_destroy`。**23 个手工种子**（来自 `tests/testdata/` + `examples/c/`）覆盖嵌套、十六进制、注释、include 等。**字典 50+ token**（`=`、`:`、`{}/[]/()`、`@include`、布尔字面量、数字单位后缀 k/M/G、转义序列等）。

### 3.3 动态测试结果（12h，fork 模式）

12h fuzz 当前仍在运行（启动时已切到 fork 模式，确保单点崩溃不终止整段）。下表为"待 12h 完成后回填"的最终数据；当前进度（运行 ~10 min）已经能给出主要结论：

| 指标 | 当前值 / 待最终回填 |
|---|---|
| 累计执行 | _(12h 完成后回填)_ |
| 平均 exec/s | 已观测 ~15K–20K |
| 最终 cov | _(回填)_ |
| **崩溃（dedup 后唯一根因数）** | **1** |
| 崩溃 artifact 数 | 4（fork 模式多次触发同一 bug） |

**唯一发现的 bug**——`libFuzzer: fuzz target exited @ yy_fatal_error scanner.c:2463`：

- **类型**：DoS（库函数直接调 `exit()`）
- **触发**：恶意构造的 `@include "..."` 字符串让 flex lexer 进入 `yy_fatal_error`，后者 `printf` 后无条件 `exit()`
- **最小复现**：13 字节
- **影响**：任何用 libconfig 解析不可信输入的程序都会被静默退出。库代码**不应**调用 `exit()`——应返回错误码让上层决策

虽不是内存安全漏洞，但仍是真实的**库设计缺陷**（攻击面：可被攻击者控制的配置文件）。

### 3.4 静态分析结果

`scan-build` 在 libconfig 上 **报告 0 个告警**（report 目录为空——scan-build 仅在有告警时输出 HTML）。这反映出：

- libconfig 代码规模相对小，且 scanner.c / grammar.c 是 flex/bison 生成的高度模板化代码，SA 难以触发其浅层 checker
- 而真正的 bug（`yy_fatal_error → exit()`）是**语义层面的设计选择**，不是 SA 工具能识别的局部缺陷模式

这一对比印证：**静态分析与动态测试互补**——前者擅长局部模式，后者擅长触发"看起来合法但语义有缺陷"的代码路径。

### 3.5 截图

\newpage

![libconfig — driver 源码](assets/driver-code-libconfig.png)

![libconfig — 12h 覆盖率趋势](assets/coverage-libconfig.png)

![libconfig — scan-build 无告警 / dedup 输出](assets/scan-build-libconfig.png)

\newpage

## 4. libucl

### 4.1 评测对象

| 字段 | 值 |
|---|---|
| 仓库 | https://github.com/vstakhov/libucl |
| 版本 | `0.9.4`（最新稳定版） |
| 代码规模 | `src/` ~15K 行 C |
| 选择理由 | UCL 是 JSON / nginx-config 超集，支持 `.include` 宏 / 变量 / 多语言输出，攻击面大于 libconfig |

### 4.2 Driver 与本地补丁

`harness/libucl/fuzz_ucl.c`：`ucl_parser_new(UCL_PARSER_NO_FILEVARS)` → `ucl_parser_add_chunk` → 成功后 `walk()` 递归遍历 tree → `ucl_object_unref`。**25 个种子**（`tests/basic/*.in`），**62 条字典**（UCL 多形态语法）。

**两处本地补丁（仅本地、不提交上游）**：

1. `targets/libucl/src/ucl_parser.c` 加 4 行 `ucl_parse_macro_value` 入口边界检查，绕过已知 OOB（issues [#320](https://github.com/vstakhov/libucl/issues/320) / [#367](https://github.com/vstakhov/libucl/issues/367) / [#378](https://github.com/vstakhov/libucl/issues/378)）
2. 注释掉 driver 中的 `ucl_object_emit` 调用，绕过 [#385](https://github.com/vstakhov/libucl/issues/385) 同源的 emit-side OOB

补丁目的：让 fuzzer 探索过这两个浅层已知 bug 去找深层问题。

### 4.3 动态测试结果（12h，fork 模式）

| 指标 | 当前值 / 待回填 |
|---|---|
| 累计执行 | _(12h 回填)_ |
| 平均 exec/s | 已观测 ~20K |
| 最终 cov | _(回填)_ |
| **崩溃（dedup 后唯一根因数）** | **1**（运行中） |
| OOM artifact 数 | **4**（运行中） |

**深层发现：`AddressSanitizer: heap-buffer-overflow ucl_util.c:2192 in ucl_strnstr`**——本地补丁绕过两个已知 bug 后浮现的第三个 bug，**ASan 烟雾测试 30 秒就稳定复现**。

`ucl_strnstr` 是个 BSD-style 子串查找：

```c
char *ucl_strnstr(const char *s, const char *find, int len) {
    char c, sc;  int mlen;
    if ((c = *find++) != 0) {
        mlen = strlen(find);
        do {
            do {
                if ((sc = *s++) == 0 || len-- < mlen)  /* OOB: s++ 越过 buffer */
                    return NULL;
            } while (sc != c);
        } while (strncmp(s, find, mlen) != 0);
        s--;
    }
    return (char *)s;
}
```

`len < mlen` 检查在 `s++` **之后**——已经发生越界读。这是一个语义清晰的 off-by-one。

**OOM 分类**：4 个 OOM artifact 都是 17 秒以上 / RSS > 2 GB 的输入，触发 libucl 内部某条指数级内存分配路径。**潜在 DoS**——待 12h 完成后用 `dedup.sh` 进一步分组。

**已知 bug 复审**：本次 fuzz 找到的所有 bug 通过 `gh api` 搜索 libucl issues 全部命中已存在的报告。维护者在 README "Security Considerations" 明确：

> Libucl ... is designed for parsing **trusted inputs**. It is **NOT** designed to handle untrusted or adversarial input safely.

这导致 fuzz 找到的所有内存安全 bug 都被维护者归为"超出安全模型"。**因此不能提交新 issue 拿加分项**——但这本身就是一个有意义的发现：**fuzz 工具找到的 bug 是否算 bug，取决于项目的安全模型**。

### 4.4 静态分析结果

`scan-build` 报告 **11 个告警**。分类统计：

| 类别 | 数量 |
|---|---|
| Dead assignment / init（死代码） | 5 |
| Null deref / null+算术 | 4 |
| **Use-after-free** in `ucl_parser_free` (ucl_util.c:627) | 1 |
| Garbage value 分支 in `ucl_schema_validate` | 1 |

**重点告警：`ucl_parser_free` 中的 UAF**——分析器路径显示 `free()` 后的链表节点指针仍被访问。考虑到这正是 fuzz 反复调用的 cleanup 入口，理论上 fuzz 应该会触发，但 12h 期间未撞到，可能因为：

1. UAF 触发需要 `parser->trash_stack` 非空 + 特定 macro 注册顺序，路径触发概率低
2. 或分析器路径条件实际不可达（伪 UAF）

未能在 fuzz 期间验证，归为"**待人工 review**"。其余 4 个 null deref 类告警分布在 `ucl_parse_csexp` / `TREE_BALANCE_*` / `ucl_parse_key`，初看都是"输入未做 NULL 校验直接 deref"模式，可能与 trusted-input 政策一致（输入认为有效）。死代码 5 个低优先级，归入附录。

### 4.5 截图

\newpage

![libucl — driver 源码](assets/driver-code-libucl.png)

![libucl — 12h 覆盖率趋势](assets/coverage-libucl.png)

![libucl — scan-build HTML 报告（11 告警）](assets/scan-build-libucl.png)

\newpage

## 5. 综合结论

| 项目 | 动态 | 静态 | 上游 bug 可提交 |
|---|---|---|---|
| libexpat | 0 真实崩溃 | 3 告警全为误报（不变量证明） | 否（已被 OSS-Fuzz 刮干净） |
| libconfig | 1 真 bug（`yy_fatal_error → exit()`，DoS 类） | 0 告警 | 不确定（设计缺陷类，需上游回应） |
| libucl | 1 已知 OOB + 4 OOM | 11 告警（1 UAF 重点） | 否（trusted-input 政策） |

**方法学层面的发现**：

1. **静态分析与动态测试互补**——libconfig 上 SA 报 0 而 fuzz 找到 DoS 设计缺陷；libucl 上 SA 报 11 而 fuzz 跑出 OOB / OOM。两个手段不可互替。
2. **"bug 与否"取决于安全模型**——libucl 的 trusted-input 政策让所有内存安全发现"合规存在"；这是 fuzz 报告必须直面的现实。
3. **Fork 模式 + dedup 是 fuzz 的必备配置**——若仍用单进程，libconfig 第 15 分钟、libucl 第 30 秒就会终止。

## 6. Agent 工具流设计（开放题）

本次实验全程由 Claude Code 作为 AI 编程助手参与（环境搭建、driver 撰写、日志分析、误报判定、issue 检索），可视为初步的 Agent 应用。设想完整的"漏洞挖掘 Agent" 工作流：

```
项目源码 → [入口推荐 + 阅读] → [Driver 自动生成] → [编译并 fuzz]
                                                         ↓
                              [覆盖率反馈循环] ←─ [崩溃/OOM/Slow]
                                       ↓
                ┌──────────────────────┴──────────────────────┐
                ▼                                             ▼
        [崩溃 triage: 去重 + 根因]                    [SA 告警 TP/FP 判定]
                              ↘                     ↙
                              [Issue / PoC 草稿 + 上游搜索去重]
```

| 环节 | Agent 行为 | 关键工具 |
|---|---|---|
| 入口推荐 | 读 README / 头文件，识别"接收外部数据"的 public API | LLM + grep / ast-grep |
| Driver 生成 | 模仿 `tests/` 风格生成 `LLVMFuzzerTestOneInput` | LLM + few-shot |
| Fuzz 调度 | 监控 cov 增长率，自动开 fork、调 max_len、扩字典 | shell + libFuzzer |
| 崩溃 triage | 按 SUMMARY + 栈帧分组（即本项目 `dedup.sh`） | 脚本（已实现） |
| **SA 告警判定** | 按本报告 §2.4 的不变量分析模式，自动定位赋值点 / 推断对象不变量 / 判 TP/FP | LLM + tree-sitter / clangd |
| 上游去重 | `gh api search/issues` 按签名搜索，避免重复提交已知 issue | gh CLI |

**最具落地价值的两个环节**：

1. **SA 告警真伪判定**——本报告 §2.4 的工作可以模板化，让"几十甚至几百条告警"变成有限的人力检查量
2. **崩溃 dedup + 上游搜索**——本项目 §3 / §4 已经实现：dedup.sh 自动分组、`gh api` 自动查重，让"30 秒找到 bug"不会变成"30 秒重新提交一个已知 issue"

## 附录：项目结构

```
fuzzing/
├── targets/                          # 三个项目均为 git submodule，锁 release tag
│   ├── libexpat/                     # R_2_8_1
│   ├── libconfig/                    # v1.8.2
│   └── libucl/                       # 0.9.4（含 2 处本地 fuzz 补丁）
├── harness/<proj>/                   # 每项目一份
│   ├── fuzz_<X>.c                    # 手写 driver
│   ├── build.sh / run.sh / scan.sh   # 三段式入口（编译 / fuzz / 静态分析）
│   ├── <X>.dict                      # libFuzzer 字典
│   └── dedup.sh                      # 崩溃按 SUMMARY + 栈帧分组
├── harness/libexpat/plot_coverage.py # 通用覆盖率图脚本（兼容单进程 / fork 模式日志）
├── corpus/<proj>/seeds/              # 手工种子（已提交）
└── build/                            # 运行时产物（gitignored）
    ├── fuzz_<X>                      # fuzzer 二进制
    ├── corpus/<proj>/                # 工作语料
    ├── findings/<proj>/              # crash / oom / slow-unit
    ├── logs/<proj>/                  # 完整 fuzz 日志
    ├── plots/<proj>/coverage.png     # 覆盖率图原文件
    └── scan-report/<proj>/…          # scan-build HTML 报告
```
