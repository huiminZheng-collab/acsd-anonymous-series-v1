# 实现笔记：模块拆分与可复用/重写判断

> 任务 B 交付物。给 GPT/作者"实际编码"阶段的参考。判断基于 2026-09-12
> 对 v2 release 与 v1 代码库的实际核验。

## 0. 2026-09-13 已落地的简化

早期建议的完整 `acsd/` 包拆分没有机械照搬；当前体量不需要十几个包内
模块。实际落地的是六个安全边界清楚的平面模块：

- `canonical_json.py`：唯一的受限 JSON 字节规范；
- `bundle_validation.py`：唯一的 PEC、governance、事件链和 policy 验证；
- `release_adapter.py`：无 I/O 的 release 到 PEC binding 投影；
- `legacy_adapter.py`：v1 文件、Node 子进程和旧元数据检查的隔离边界；
- `key_identity.py`：唯一的公钥标识定义；
- `cli_output.py`：唯一的 CLI 退出码和输出序列化定义。

`acsd.check_bindings` 与 `pec_core.validate_pec` 保留为兼容入口，但不再各自
实现安全规则。`acsd.py` 因此减少约 105 行，`pec_core.py` 减少约 112 行；
新增模块的目的不是追求仓库总行数下降，而是让每条安全规则只有一个权威
实现。审批集合的文件收集和纯集合验证也已经分开。当前剩余的大块工作是
按行为语料逐步拆分 CLI 命令编排，不再为了目录形式机械拆包。

## 1. 建议的 Python 包结构

```
acsd/
├── cli.py           # argparse 入口、子命令分发、--json/--quiet、退出码
├── canonical.py     # canonical()/_check_json()，从 pec_core 提取 + 补丁 P1/P3
├── keys.py          # Ed25519 生成/加载（PKCS#8 PEM, 0600）、签名、公钥指纹
├── cose.py          # COSE Sign1 构造与解析（Ed25519/EdDSA; alg -8）
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
| `canonical()` / `_check_json()` | `canonical_json.py`（由 `pec_core.py` 兼容导出） | 已完成单一定义及 Python/Node 差分 |
| `validate_pec` 绑定检查 | `bundle_validation.py` | 已由 CLI 与旧 facade 共同调用，错误码回归覆盖 |
| `verify_legacy_disclosure_metadata` / dialogue Merkle | `legacy_adapter.py` / `pec_core.py` | 旧元数据入口已隔离且仅用于兼容；授权性事件揭示走 `event_disclosure.py` |
| `verify_sidecar_subject` | `pec_core.py` | 平移，作为 `tsa.py` 的 scope 前置检查 |
| release projection / v1 standalone package | `release_adapter.py` / `legacy_adapter.py` | 活跃路径只用纯投影；旧公开名称由 `pec_core.py` 延迟转发 |
| `verify_demo.py` / `verify_release.py` 的 manifest 逻辑 | 根目录 | 平移至 `package.py`，加 symlink 拒绝 |
| 错误码与输出格式 | `canonical_json.require` / `cli_output.py` | 条件错误码与进程退出/序列化边界分别单一定义 |
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
