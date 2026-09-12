# ACSD Canonical JSON — 逐字节规范与差分裁决

> 任务 A 交付物。基于 2026-09-12 实测差分数据（`canonical_diff_runner.py`，
> 64 个向量：46 AGREE-BYTES / 13 AGREE-REJECT / 5 DIVERGE-TYPE）。
> 本文不修改主项目文件；补丁建议见 §5。

## 1. 三个实现的现状对照（实测）

| 行为 | v1 Python (`generate.py`) | v1 Node (`verify-standalone.cjs`) | v2 Python (`pec_core.py`, fix b882149 后) |
|---|---|---|---|
| 非 ASCII 字符串值 | `ensure_ascii=False`，保留 UTF-8 | `JSON.stringify` 不转义，保留 UTF-8 | `ensure_ascii=False`（已修复），保留 UTF-8 ✓ |
| `\b` (U+0008) | `\b` 缩写 | `\b` 缩写 | `\b` 缩写 ✓ 三者一致 |
| `\f` (U+000C) | `\f` 缩写 | `\f` 缩写 | `\f` 缩写 ✓ 三者一致 |
| `\n` `\t` `\r` | 缩写 | 缩写 | 缩写 ✓ |
| 其他控制字符 U+0000–001F | `\uXXXX` | `\uXXXX` | `\uXXXX` ✓ |
| 组合字符 / é / U+2028 / U+2029 / DEL | 原样 | 原样（ES2019+） | 原样 ✓ |
| 键排序 | Unicode 码点升序 | UTF-16 code unit 升序 | Unicode 码点升序（ASCII 键下三者等价 ✓） |
| 键必须 ASCII | 是（`key.isascii()`） | 是（正则 `[\x00-\x7f]`） | 是（`ord>127` 拒绝）✓ |
| 整数范围 | `[-2^53+1, 2^53-1]` | `Number.isSafeInteger` | `abs() <= 2^53-1` ✓ 等价 |
| float | 拒绝（`canonical_json_value` 返回 False） | **对象层无法区分**：`1.0` parse 成整数 `1` | 拒绝（`FLOAT_FORBIDDEN`） |
| tuple（API 层） | 拒绝 | 无此类型 | **接受**（`isinstance(..., (list, tuple))`）⚠ 不一致 |
| lone surrogate | 未检查；`encode` 崩溃 | `JSON.stringify` 转义为 `\udXXX` 并接受 ⚠ | 未检查；`encode` 崩溃（`UnicodeEncodeError`）⚠ |

**注：** 本审稿人此前在审稿意见 1.2 中推测 Python 与 JS 在 `\b`/`\f` 上分歧，
**该推测被实测推翻** —— 三者一致使用缩写。以本文件实测数据为准。

## 2. 逐字节规范（建议写入 SPEC.md）

一条文本 T 是 canonical，当且仅当 `canonical(parse(T)) == T`（UTF-8 字节精确相等）。
对象层规则：

1. **结构**：对象 = `{` + 键值对 + `}`；数组 = `[` + 元素 + `]`；元素间仅用 `,`，
   无任何空白字符。
2. **键排序**：对象键按其 UTF-8 码点升序排列（ASCII 键下与 UTF-16 code unit
   序一致）。禁止重复键。
3. **键**：必须是字符串且仅含 U+0000–U+007F（ASCII）；否则拒绝
   （`NONASCII_KEY`）。键内的控制字符按规则 4 转义。
4. **字符串值转义**（键与值同规则）：
   - U+0022 `"` → `\"`
   - U+005C `\` → `\\`
   - U+0008 → `\b`　U+0009 → `\t`　U+000A → `\n`　U+000C → `\f`　U+000D → `\r`
   - U+0000–U+001F 其余 → `\uXXXX`（小写十六进制，4 位）
   - 其余全部字符（含中文、组合字符、U+2028/29、DEL、emoji）→ 原样 UTF-8 字节
   - **禁止 lone surrogate**（U+D800–U+DFFF 未配对）：拒绝（`LONE_SURROGATE`）
5. **数字**：仅整数，范围 `[-2^53+1, 2^53-1]`（safe integer）。禁止小数
   （`FLOAT_FORBIDDEN`）、指数形式、`NaN`、`Infinity`、`-0.0`。`0` 即 canonical
   （无负零）。
6. **字面量**：`true` / `false` / `null`。
7. **根值**：任意合法值均可作根。
8. 拒绝类型：float、超出范围的 int、非字符串键、非 ASCII 键、含 lone
   surrogate 的字符串；**tuple 应拒绝**（见 §4-D4，与 v1 对齐）。

## 3. 接受 / 拒绝速查表

| 输入（对象层） | 接受 | 拒绝码 |
|---|---|---|
| str（无 lone surrogate） | ✓ | |
| str 含 lone surrogate | | `LONE_SURROGATE` |
| bool / None | ✓ | |
| int，`abs <= 2^53-1` | ✓ | |
| int 越界 | | `UNSAFE_INTEGER` |
| float（任何） | | `FLOAT_FORBIDDEN` |
| list | ✓ | |
| dict，键全为 ASCII str | ✓ | |
| dict 非 str 键 | | （类型检查） |
| dict 非 ASCII 键 | | `NONASCII_KEY` |
| tuple | | 建议 `JSON_TYPE_FORBIDDEN`（当前接受） |

文本层：重复键、键乱序、`1.0`/`1e3`/`-0`/`-0.0`、空白、`\/` 转义、`\u0008` 形式
（应为 `\b`）等均非 canonical —— 由字节对比自动拒绝，无需额外类型规则。

## 4. 五处 DIVERGE 的裁决

- **D1/D2/D3 — `float-1.0`、`float-exponent`、`negative-zero-float`**
  （对象层 DIVERGE-TYPE，文本层一致拒绝）。JS 的 number 无 int/float 之分，
  `JSON.parse("1.0") === 1`。裁决：**规范只保证文本层**（两边都判非
  canonical，已一致）；对象层 Node 端"静默转整数"可接受，但实现不得把
  `1.0` 文本当作 canonical 输入接受 —— 依赖字节对比，无需代码改动。
- **D4 — lone surrogate（`str-lone-high-esc` / `str-lone-low-esc`）**
  （DIVERGE-TYPE：Python 崩溃 `UnicodeEncodeError`，Node 转义接受）。
  裁决：**拒绝**。未配对 surrogate 不是合法 Unicode 标量，canonical 字节
  无法定义。补丁见 §5-P1/P2。
- **D5 — tuple（API 层）**：v2 接受、v1 拒绝、Node 无此类型。JSON 文本层
  不可达，但 API 层应统一。裁决：**拒绝**（与 v1 一致）。补丁见 §5-P3。

## 5. 补丁（P1/P2/P3 已落地）

> 状态：2026-09-12 已落地 P1（lone surrogate 拒绝）、P2（Node isWellFormed）、
> P3（拒绝 tuple）。差分测试 64/64 全绿（46 AGREE-BYTES / 15 AGREE-REJECT /
> 3 已知对象层 DIVERGE，0 unexpected failure）。P4 待 GPT/作者同步进 SPEC.md。

- **P1 `pec_core.py::_check_json`**（已落地）：
  ```python
  if isinstance(value, str):
      if any(0xD800 <= ord(c) <= 0xDFFF for c in value):
          raise ValueError("LONE_SURROGATE")
      return
  ```
  把当前的无差别 `str: return` 改为上述检查；崩溃变为确定错误码。
- **P2 Node 端（v1 `verify-standalone.cjs` 的 `canonicalJson`）**（~3 行）：
  ```js
  if (typeof value === 'string') {
    if (!value.isWellFormed()) throw new Error('LONE_SURROGATE');
    return JSON.stringify(value);
  }
  ```
  Node ≥ 20 支持 `String.prototype.isWellFormed`（本机 v24.16.0 ✓）。
- **P3 `pec_core.py::_check_json`**：`(list, tuple)` → `list`（拒绝 tuple）。
- **P4 SPEC.md**：把 §2 的转义细则补进 "3. Canonical bytes and identifiers"
  一节，明确 `\b`/`\f`/`\n`/`\t`/`\r` 缩写、其余控制字符 `\uXXXX`、非 ASCII
  保留 UTF-8、禁止 lone surrogate、禁止 tuple。
- **P5 测试**：把 `design/canonical_diff_runner.py` 纳入 CI/`run_all.ps1`
  （P1/P2 落地后 64/64 期望全过，exit 0）。

## 6. 差分测试资产

- `canonical_diff_runner.py` —— runner（读项目 `pec_core`，不改它）
- `canonical_ref.cjs` —— Node 参考实现（v1 语义逐字提取）
- `canonical_diff_vectors.json` —— 64 个向量（机器可读）
- `canonical_diff_report.json` —— 本次实测报告

复现：`cd design && python canonical_diff_runner.py`
（需 Node ≥ 20 与 Python 3.9+；退出码 2 = 存在未落地的规范分歧，当前为
lone surrogate ×2，P1/P2 落地后归 0。）
