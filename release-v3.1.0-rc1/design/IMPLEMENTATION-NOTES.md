# 实现笔记：模块拆分与可复用/重写判断

> 任务 B 交付物。给 GPT/作者"实际编码"阶段的参考。判断基于 2026-09-12
> 对 v2 release 与 v1 代码库的实际核验。

## 1. 建议的 Python 包结构

```
acsd/
├── cli.py           # argparse 入口、子命令分发、--json/--quiet、退出码
├── canonical.py     # canonical()/_check_json()，从 pec_core 提取 + 补丁 P1/P3
├── keys.py          # Ed25519 生成/加载（PKCS#8 PEM, 0600）、签名、公钥指纹
├── cose.py          # COSE Sign1 构造与解析（Ed25519; -35 曲线标签）
├── release.py       # PaperRelease 构建/验证（真实 PDF 内容摘要，替换 demo 占位符）
├── governance.py    # AuthorshipGovernanceStatement + team.json 解析
├── pec.py           # PEC body 构建/验证（复用 validate_pec 绑定逻辑）
├── events.py        # 事件链 + salted Merkle dialogue（从 pec_core 平移）
├── policy.py        # claim_policy / non-claims 常量（与 SPEC.md 对齐）
├── tsa.py           # RFC 3161 客户端 + 离线验证（imprint/nonce/CMS/chain/genTime）
├── package.py       # manifest 生成/验证、staging+rename 原子写入、路径/symlink 检查
├── state.py         # 状态机（CLI-SPEC §3 的迁移表）
├── errors.py        # 错误码表 + 退出码映射（CLI-SPEC §4）
├── verify.py        # 全验证编排（canonical→签名→绑定→链→manifest→TSA）
└── node_bridge.py   # 可选：调 v1 verify-standalone.cjs 做交叉验证
tests/               # 与模块一一对应；M-* 矩阵全部落位
```

## 2. 现有实现逐项判断

### 可复用（改动小）

| 资产 | 位置 | 复用方式 |
|---|---|---|
| `canonical()` / `_check_json()` | `pec_core.py` | 平移至 `canonical.py`，落地补丁 P1（lone surrogate）+ P3（tuple） |
| `validate_pec` 绑定检查 | `pec_core.py` | `pec.py` 复用其逻辑，错误码保留 |
| `verify_legacy_disclosure_metadata` / dialogue Merkle | `pec_core.py` | 旧元数据入口仅用于兼容；授权性事件揭示走 `event_disclosure.py` |
| `verify_sidecar_subject` | `pec_core.py` | 平移，作为 `tsa.py` 的 scope 前置检查 |
| `adapt_v1_release` / `validate_v1_standalone_package` | `pec_core.py` | v1 互操作层保留，按需启用 |
| `verify_demo.py` / `verify_release.py` 的 manifest 逻辑 | 根目录 | 平移至 `package.py`，加 symlink 拒绝 |
| 错误码风格（`require(cond, code)`） | `pec_core.py` | 保留，扩展至 CLI 全路径 |
| v1 Node verifier `verify-standalone.cjs` | v1 代码库 | **打包进 release**（或 pin 版本+校验和），作为交叉验证第二实现 |
| v1 fixtures（8 releases/18 endorsements/13 scenarios） | v1 代码库 | 作为集成测试输入（需真实私钥重签或使用 v1 私钥仅限测试） |

### 必须重写 / 新增

| 缺口 | 原因 | 工作量估计 |
|---|---|---|
| COSE Sign1 **签名** | v2 只有委托 Node 的**验证**路径，没有签名器；无 Python COSE 实现 | 中（Ed25519 COSE Sign1 结构简单：protected header alg=-35 + payload，可用纯 Python 构造，但需与 Node 验证器互操作测试） |
| RFC 3161 客户端 | v2 只有 `verify_sidecar_subject` 的 scope 检查，无请求构造、无 CMS 解析 | 中（`tsq` 构造简单；`tsr` 验证需 CMS/SignerInfo 解析 —— 自研 or 用 `cryptography` 库，放弃零依赖） |
| 真实 release/governance 生成 | demo 用 `"a"*64` 占位符；需从真实 PDF 生成内容摘要与对象 | 小（逻辑已有，替换数据源） |
| CLI 层 | 不存在 | 小-中（argparse + 状态机 + JSON 输出） |
| 原子包构建 | `generate_demo.py` 直接写 demo/；需 staging+rename | 小 |
| keygen / 密钥管理 | 不存在 | 小（`cryptography` 或 `PyNaCl`；若坚持零依赖则 Ed25519 自研**不建议**） |
| 状态机 | 不存在 | 小 |
| 三平台 CI + 安装入口 | 不存在 | 小（pyproject + GitHub Actions） |

## 3. 关键架构决策点（留给 GPT 裁决）

1. **零依赖 vs `cryptography`**：v2 原则是"零依赖"。但 RFC 3161 响应验证
   （CMS）与 Ed25519 用零依赖自研意味着**自己实现密码学**——违背 v1 已
   有的"audited Node verifier"边界。建议：**签名验证走 COSE 自研最小集 +
   Node verifier 交叉验证；RFC 3161 的 CMS 解析用 `cryptography`**（其维护
   性远高于自研），"零依赖"降级为"零依赖验证核心 + 可选强依赖的 TSA 模块"。
2. **Node verifier 的定位**：作为"独立第二实现"打包，`verify` 默认跑双实现
   交叉（Python 主 + Node 复验，不一致即报警）。这比"纯 Python 自证"强一档。
3. **密钥格式**：Ed25519 + PKCS#8 PEM（`cryptography` 生成）最通用；seed 备份
   用 bech32 或 BIP39 词表（可选）。
4. **CLI 单一入口**：`python -m acsd` + console_script `acsd`；Windows 用
   `pipx` 或 zipapp。不做 exe 打包（范围外）。

## 4. 顺序建议（对齐 GPT 的六块缺口）

1. canonical 补丁（P1/P3）+ 差分测试绿 → 2. 真实 fixture 生成 →
3. COSE 签名器 + Node 交叉 → 4. 状态机 + 包原子构建 →
5. RFC 3161 → 6. CLI + CI + 文档。
每步独立可验证，符合"1–2 周 MVP"节奏。
