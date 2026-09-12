# ACSD 开箱即用 CLI 规格（草案 v0.1）

> 任务 B 交付物。目标：作者本地可用的 CLI MVP。本规格只描述接口与状态机，
> 不绑定实现语言细节；最终架构由 GPT/作者裁决。

## 1. 命令接口

```
acsd init    <paper.pdf> --team team.json [--out release-dir] [--work-id urn:uuid:...]
acsd approve <release-dir> --key author-key.pem [--role CRediT-role]
acsd finalize <release-dir> [--tsa https://tsa.example] [--allow-untimestamped]
acsd verify  <release-dir>
acsd inspect <release-dir>
acsd release <paper.pdf> --team team.json --key author-key.pem [--tsa URL]   # 单作者快捷
```

通用选项：`--json`（机器可读输出）、`--quiet`、`--dry-run`。

- `init`：读取 PDF 字节，生成 WorkID（若无 `--work-id` 则随机 UUID）、
  内容摘要、release 对象、governance 草稿、PEC 草稿、密钥位（不生成密钥）、
  `state.json = awaiting-approvals`。**幂等**：对同一 PDF+team 重跑返回同一
  release digest。
- `approve`：作者用自己的私钥对 canonical release 字节签发 COSE Sign1，
  写入 `endorsements/`。重复批准（同 key）→ 错误 `DUPLICATE_APPROVAL`。
  未知 key（不在 team）→ 错误 `UNKNOWN_AUTHOR_KEY`。顺序无关（作者可在
  不同机器、不同时间签名，通过 U 盘/邮件传递 `release-dir`）。
- `finalize`：检查全部必需签名 → 组装 PEC → 全体作者对 PEC 签发 → 可选
  RFC 3161 → 原子生成最终目录 + `MANIFEST.sha256` → 状态 `finalized`（或
  `finalized-untimestamped`）。缺签名 → `APPROVALS_INCOMPLETE`（列出缺谁）。
- `verify`：从零重算：canonical 校验、COSE 签名、content digest、governance
  绑定、PEC 链、事件链、manifest 覆盖、可选 RFC 3161 离线验证。输出
  granted outcomes + non-claims。**只读**。
- `inspect`：打印状态机状态、缺哪些签名、WorkID、release digest、TSA 状态、
  文件清单。**只读**。
- `release`：`init`+全部 `approve`+`finalize` 的一条命令（仅当 team 只有
  一名作者且该作者持有唯一密钥；否则报错要求分步）。

## 2. 目录结构（发布包）

```
release-dir/
├── state.json                  # 状态机（见 §3）
├── team.json                   # 输入原样存档
├── paper/
│   └── <sha256>.pdf            # 内容寻址、不可变
├── release/
│   └── release.json            # PaperRelease（canonical）
├── governance/
│   ├── statement.json          # AuthorshipGovernanceStatement
│   └── endorsements/<key-id>.cose
├── pec/
│   ├── pec.json                # PEC body
│   └── approvals/<key-id>.cose
├── receipts/                   # 可选
│   ├── request.tsq  response.tsr  chain.pem  report.json
└── MANIFEST.sha256             # 覆盖以上所有文件（除自身）
```

**不变量：**
- 私钥**永不**出现在 `release-dir` 内（approve 只读 key，不复制）。
- 所有内容文件不可变（内容寻址）；状态变化只发生在 `state.json` 与
  `endorsements/`、`receipts/`。
- 无绝对路径、无本机用户名、无环境变量值、无本地时钟（TSA `genTime`
  除外）、无 Git 元数据进入包内。
- 行尾统一 `\n`（跨平台）。

## 3. 状态机

```
                 init
                  │
                  ▼
         awaiting-approvals ──(approve×N，非全员)──► awaiting-approvals
                  │
       (finalize，签名齐全)
                  │
        ┌─────────┴──────────┐
        ▼                    ▼
  finalizing        (TSA 不可达且 --allow-untimestamped)
        │                    │
        ▼                    ▼
   finalized ◄───────  finalized-untimestamped
```

- 允许的状态迁移表：
  `awaiting-approvals → awaiting-approvals`（新签名）、
  `awaiting-approvals → finalizing → finalized`（TSA 成功）、
  `awaiting-approvals → finalizing → finalized-untimestamped`（降级）、
  `finalized* → finalized`（事后补时间戳：新 tsq/tsr + 新 manifest 条目）。
- 非法迁移（如 `finalized` 后再 `approve`）→ `STATE_CONFLICT`。
- `finalizing` 是短暂中间态：任何失败都回退到 `awaiting-approvals`，
  **不留半成品目录**（见 §5 原子性）。

## 4. 退出码

| 码 | 含义 | 示例 |
|---|---|---|
| 0 | 成功 | `verify` 全过 |
| 1 | 验证失败 | 签名无效、digest 不匹配、manifest 不一致 |
| 2 | 用法错误 | 未知子命令、缺参数 |
| 3 | 状态机冲突 | 对 `finalized` 再次 `finalize` |
| 4 | 外部服务失败 | TSA 超时 / HTTP 5xx（`finalize --tsa`） |
| 5 | 批准不完整 | `finalize` 时缺作者签名（`APPROVALS_INCOMPLETE`） |

## 5. 原子性与失败语义

1. `finalize` 先把完整最终目录写进 `<release-dir>.staging/`，全部校验通过后
   原子 `rename` 到最终名；失败则删除 staging。
2. 因此 `release-dir` 永远只有两种形态：**进行中**（`awaiting-approvals`，
   目录不完整是显式的）或**完整**（`finalized` + manifest 可验证）。不存在
   "看似完整其实缺东西"的第三态。
3. `verify` 对任何目录都明确报告：`VALID`（finalized 且全过）、
   `INCOMPLETE`（缺批准）、`TAMPERED`（digest/manifest 不符）、
   `DEGRADED`（finalized-untimestamped）。
4. TSA 失败不破坏已有签名：已签的 `endorsements/` 原样保留，仅状态回退。

## 6. JSON 输出格式（--json）

每个命令输出单行 JSON 对象（LF 结尾）：
```json
{
  "command": "finalize",
  "status": "ok | error",
  "exit_code": 0,
  "message": "human-readable summary",
  "data": { "release_digest": "...", "pec_digest": "...", "state": "finalized",
            "granted_outcomes": ["KEY_ASSENT", "GOVERNANCE_ASSENT"],
            "non_claims": ["natural_person_authorship", "..."] }
}
```
错误时 `data` 含 `error_code`（如 `APPROVALS_INCOMPLETE`）与 `missing_keys`。
`verify` 的 `data` 必须**同时**携带 granted outcomes 与 non-claims —— 程序化
消费方不得只读前者。

## 7. 密钥与多人工作流

- 密钥生成：`acsd keygen`（默认 Ed25519，PKCS#8 PEM；私钥权限 0600，
  存 `~/.acsd/keys/`，**绝不**写入 release-dir）。`team.json` 只含公钥与
  角色槽位：
  ```json
  {"schema": "acsd-team/v1",
   "authors": [{"slot": 1, "role": "Conceptualization", "key_id": "sha256:<pubkey-hex>",
                "corresponding": true}]}
  ```
- 多人：每位作者在自己机器 `keygen` → 公钥发给协调者 → `init` → 协调者把
  `release-dir` 打包传给每人 → 各自 `approve` → 回传 → `finalize`。
- 撤销/轮换：`finalize` 后不支持改作者集（内容已定）。需要变更 → 新版本
  release（`init --parent`）。密钥泄露 → 发布 `key-revocation.json` sidecar
  （进包外、独立分发）。

## 8. RFC 3161 集成（finalize --tsa）

1. 只发送 **SHA-256 imprint**（`pec_digest`），携带随机 nonce；请求与响应
   的原始 DER（`.tsq`/`.tsr`）、证书链、验证报告全部入包。
2. TSA 不可达：默认失败（exit 4，状态回退，已有签名保留）；显式
   `--allow-untimestamped` 才降级为 `finalized-untimestamped`，且
   `state.json` 与输出都显著标注降级。
3. `verify` 离线检查：imprint 匹配、nonce 匹配、CMS 签名、TSA 证书链
   （pin 或系统信任）、`genTime` 读取。**输出只声明
   `EXTERNALLY_NOT_AFTER`**，绝不声明"创作时间"或"原创性"。
4. 禁止把 Git 时间、本地时钟、见证观察当作时间证据（沿用 claim_policy）。

## 9. 跨平台

- 纯 `pathlib` + `argparse`；无 shell 调用（RFC 3161 用 `http.client`）。
- 路径处理拒绝 `..`、绝对路径、盘符（Windows 校验）。
- 换行统一 `\n`；PEM/JSON 一律 UTF-8 无 BOM。
- CI 矩阵：Windows / macOS / Linux（Python 3.9+）。

## 10. 声明边界（产品层）

- 所有输出必须携带 non-claims 五元组：`natural_person_authorship`、
  `contribution_truth`、`originality_truth`、`legal_nonrepudiation`、
  `peer_review`。
- 帮助文本与 README 禁止出现"证明作者身份""证明创作时间""防止抄袭"等
  措辞；允许的措辞见 SPEC.md 的 claim_policy 表。
- `verify` 的 `EXTERNALLY_NOT_AFTER` 只绑定"TSA 见到该 imprint 不晚于
  genTime"。

## 11. 范围外（明确不做，v1.0 前）

- 多机构交叉系列包（跨 series）、透明日志/见证服务、zero-knowledge 选择性
  披露、作者身份链接、BBS/匿名凭据、GUI。
