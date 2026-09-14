# ACSD 开箱即用 CLI 规格（v3.0）

> 任务 B 交付物。目标：作者本地可用的 CLI MVP。本规格只描述接口与状态机，
> 不绑定实现语言细节；最终架构由 GPT/作者裁决。

## 1. 命令接口

```
acsd init    <paper.pdf> --team team.json [--out release-dir] [--parent parent-dir]
acsd authorize <release-dir> --key predecessor-key.pem
acsd approve <release-dir> --key author-key.pem
acsd finalize <release-dir> [--tsa https://tsa.example] [--allow-untimestamped]
acsd verify  <release-dir> [--expected-parent-release-id URN] [--tsa-trust-cert CERT | --tsa-trust-fingerprint HEX] [--emit-appraisal-transcript]
acsd inspect <release-dir>
acsd release <paper.pdf> --key author-key.pem [--key coauthor-key.pem] [--tsa URL]
acsd revise  <parent-dir> <paper.pdf> --key new-author-key.pem [--parent-key old-author-key.pem]
acsd compare-successors <left-dir> <right-dir>
acsd audit-key-reuse <release-dir> <release-dir> [...] [--fail-on-cross-work]
acsd verify-identity-set <release-dir> --disclosure D --signature S [...] [--require-full-byline]
```

通用选项：`--json`（机器可读输出）。

- `init`：读取 PDF 字节；首版生成随机 WorkID，续版从已验证的 `--parent` 继承 WorkID、
  内容摘要、release 对象、governance 草稿、PEC 草稿、密钥位（不生成密钥）、
  `state.json = awaiting-approvals`。已存在的非空输出目录拒绝覆盖。
- `approve`：作者用自己的私钥对 canonical approval target 签发 COSE Sign1；
  target 同时绑定 release、governance 与 PEC，签名写入 `approvals/`。
  重复批准（同 key）→ 错误 `DUPLICATE_APPROVAL`。
  未知 key（不在 team）→ 错误 `UNKNOWN_AUTHOR_KEY`。顺序无关（作者可在
  不同机器、不同时间签名，通过 U 盘/邮件传递 `release-dir`）。
- `authorize`：当作者密钥集合或 threshold 发生变化时，前序 authority 的密钥对
  exact lineage transition 签名；达到前序版本预先声明的 threshold 才有继承权。
- `finalize`：从签名文件重算全部必需批准（不信任 state 中的计数）→ 可选
  RFC 3161 → 原子生成最终目录 + `MANIFEST.sha256` → 状态 `finalized`（或
  `finalized-untimestamped`）。缺签名 → `APPROVALS_INCOMPLETE`（列出缺谁）。
- `verify`：从零重算：canonical 校验、COSE 签名、content digest、governance
  绑定、PEC 链、事件链、manifest 覆盖、可选 RFC 3161 离线验证。输出
  granted outcomes + non-claims。对后继版本可用 `--expected-parent-release-id`
  固定验证者此前认可的 parent；省略时显式报告 `UNPINNED_EXACT_PARENT`。
  `--emit-appraisal-transcript` 可额外输出真正驱动这些 outcomes 的严格类型化
  中间证据，但它本身不替代底层字节验证。**只读**。
- `inspect`：打印状态机状态、缺哪些签名、WorkID、release digest、TSA 状态、
  文件清单。**只读**。
- `release`：`init`+全部 `approve`+`finalize` 的一条命令；可重复 `--key`
  处理同一机器上合法持有的多作者私钥，分布式团队仍使用分步流程。
- `revise`：一条命令生成严格的下一版本或授权分支；新作者以 `--key` 批准完整
  target，作者集合变化时用重复的 `--parent-key` 满足前序 threshold。
- `compare-successors`：验证两个后继并检测同一 parent、line、version 的已授权
  分叉；报告 equivocation，但不替作者挑选“赢家”。
- `audit-key-reuse`：先完整验证两个或更多 release，再按公开 key ID 聚合作者
  slot；同一 WorkID 内的复用和跨 WorkID 复用分别报告。默认是只读信息审计，
  `--fail-on-cross-work` 在发现跨 WorkID 复用时返回 exit 1，方便发布前 CI。
  相等 key ID 证明公开密钥可链接，不证明背后是同一自然人。
- `verify-identity-set`：验证同一 exact release 的一个或多个 slot sidecar。
  合法子集返回 `PARTIAL_BYLINE_KEY_ASSENT`；覆盖所有且仅有的作者 slot 才返回
  `FULL_BYLINE_KEY_ASSENT`。`--require-full-byline` 将合法但不完整的集合映射为
  exit 5。重复 slot、签名错误、release/key 作用域不匹配均拒绝。

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
│   └── statement.json          # AuthorshipGovernanceStatement
├── pec/
│   └── pec.json                # PEC body
├── approval/
│   └── target.json             # jointly signed digest tuple
├── approvals/<key-id>.cose
├── lineage/                    # 仅后继版本存在
│   ├── parent-release.json
│   ├── parent-pec.json
│   ├── transition.json
│   ├── parent-public-keys/<key-id>.pub
│   └── authorizations/<key-id>.cose
├── receipts/                   # 可选
│   ├── request.tsq  response.tsr  tsa-cert.der  report.json
└── MANIFEST.sha256             # 覆盖以上所有文件（除自身）
```

**不变量：**
- 私钥**永不**出现在 `release-dir` 内（approve 只读 key，不复制）。
- 所有内容文件不可变（内容寻址）；状态变化只发生在 `state.json` 与
  `approvals/`、`receipts/`。
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
  已 finalised 的目录不可原位补写；任何补充证据形成新增版本。
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
   `VALID`（作者证据有效但可无外部时间）。
4. TSA 失败不破坏已有签名：已签的 `approvals/` 原样保留，仅状态回退。

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
只有显式请求 `--emit-appraisal-transcript` 时，`data` 才增加
`appraisal_transcript`；默认 JSON 合同保持不变。

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
- 轮换：需要变更作者集或 threshold 时，创建新版本（`init --parent`），并由
  前序 authority 按其既有 threshold 签署 exact transition。新版本不能自行
  降低前序 threshold。
- 密钥丢失：若剩余可用前序密钥不足 threshold，该 lineage 按 fail-closed
  语义冻结；仍可另起 WorkID 引用旧作，但不能冒充其后继。
- 撤销：v3 不把事后发布的 sidecar 当作可改写已经生效的历史授权。在线撤销、
  身份恢复与预承诺 recovery authority 是后续扩展，不能靠包外声明偷偷引入。

## 8. RFC 3161 集成（finalize --tsa）

1. 全部必要签名验证通过后，先构造绑定每个 exact COSE 字节串的
   `approval_set_digest`，再只发送该 **SHA-256 imprint**，携带随机 nonce；
   原始 DER、服务返回的 signer certificate 和报告入包。
2. TSA 不可达：默认失败（exit 4，状态回退，已有签名保留）；显式
   `--allow-untimestamped` 才降级为 `finalized-untimestamped`，且
   `state.json` 与输出都显著标注降级。
3. 包内 certificate 不自证可信。`verify` 只有收到外部
   `--tsa-trust-cert` 或 `--tsa-trust-fingerprint` 后，才检查 imprint、nonce、
   CMS/TSTInfo profile、ESS signer id、关键且专用的 timeStamping EKU 与签名，
   并输出 `APPROVAL_SET_EXISTED_NOT_AFTER`。旧 v0.1/v0.2 的 target-only 回执
   仍可验证，但不得升级为 approval-set 时间结论。当前模型是 exact signer pin，不是通用 PKIX
   path/revocation 验证。
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
- `verify` 的 `APPROVAL_SET_EXISTED_NOT_AFTER` 只绑定"TSA 见到完整批准集的
  imprint 不晚于
  genTime"。

## 10.1 选择性揭盲

- `disclose-identity` 只为 exact release 的一个作者 slot 生成包外 sidecar；
  不修改已冻结 release，也不替其他 slot 揭盲。
- `verify-identity` 的成功结果是
  `SLOT_KEY_ASSENT_TO_IDENTITY_ASSERTION`，不是自然人身份或会议录用验证。
- 同一 slot 的冲突陈述不自动选赢家；缺少任一 slot 时不得输出完整 byline。
- 身份 sidecar 的 exact-release 作用域不会扩张到另一篇论文；但若两篇论文
  复用同一公开密钥，key ID 等值本身已形成可观察链接。无关 lineage 默认
  使用独立密钥，并可在发布前运行 `audit-key-reuse`。

## 11. 范围外（明确不做，v1.0 前）

- 多机构交叉系列包（跨 series）、透明日志/见证服务、zero-knowledge
  或不可链接凭据、BBS/匿名凭据、GUI。直接的 slot-to-identity 公共链接已实现。
