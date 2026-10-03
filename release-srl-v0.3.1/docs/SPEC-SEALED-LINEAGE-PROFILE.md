# ACSD 密封研究谱系配置文件规范（Sealed Lineage Profile v0.3.1）

- **规范版本**：Profile v0.3.1（Hardened Prototype Candidate, Freeze Candidate）
- **发布日期**：2026-10-02
- **母协议**：ACSD（Anonymous Scholarly Claim and Disclosure）
- **依据原型**：[`research/srl_prototype/`](../research/srl_prototype/)（包含 55 项测试，覆盖 FX-01~06、REG-01~38、真实 DigiCert RFC 3161 凭据端到端 `appraise` 复验及 35 节点超长谱系链 $O(1)$ 栈空间迭代验证）
- **形式化模型**：[`research/srl_prototype/SealedLineage.lean`](../research/srl_prototype/SealedLineage.lean)（Lean 4.34.1 编译通过；13 组定理覆盖抽象输出代数与安全不变量投影，其边界见原型 README）
- **受保护状态**：本规范为独立扩展研究 profile，不改动已提交至 TCJ 的论文稿件（`COMPJ-2026-09-1289`）及当前 dirty worktree。

---

## 1. 定位、威胁模型与安全边界

本规范（`SealedLineageProfile v0.3.1`）将 ACSD 的离线证据能力从“公开版本谱系与事后身份揭露”扩展至**“长周期秘密研究推演、细粒度声明目录冻结、前驱权威授信演化与后来选择性开封”**。

### 1.1 保证达成的安全属性（Security Guarantees）

1. **加盐开封强绑定（Salted Opening Soundness）**：开封证明能且仅能打开早期已精确提交加盐承诺的材料。
2. **计算隐藏性（Computational Hiding）**：声明目录中彻底废弃无盐明文摘要，强制使用加盐承诺 $\text{SHA-256}(salt \parallel material)$，消除针对简短公式或短语的彩虹表与字典预计算攻击。
   * *安全假设说明*：验证器强制检查盐的长度不少于 32 字节（256 位）。盐的高熵性（CSPRNG 生成）属于作者端保密假设，验证器无法单凭字节检查证明其物理熵来源。
3. **基于树拓扑推导的 Merkle 包含证明与防改标重开封（Position-Derived Merkle Inclusion & Anti-Relabeling）**：
   * Merkle 包含核验函数严格接收已签名的 `leaf_index` 与 `catalog_leaf_count` ($N$)。
   * 每一层二叉折半的方向（左兄弟或右兄弟）**完全由 $(idx, W)$ 树拓扑数学推导**，严禁盲信调用者自行上报的 `direction`。
   * 验证器在开封循环中强制施加三重单射排重：`seen_leaf_indices`、`seen_claim_ids` 以及 `seen_leaf_hashes`。若攻击者试图将同一份叶 0 内容改写标为索引 1 进行重复提交，将同时被树位置推导失败、重复叶哈希拦截和重复声明 ID 拦截。
4. **开封作用域非放大（Scope Non-Amplification）**：叶节点总数 $N$ 严格固化并签名于 `ApprovalTarget.catalog_leaf_count` 中。判定 `COMPLETE_CATALOG_OPENING` 要求开封叶节点索引形成对精确集合 $\{0, 1, \dots, N-1\}$ 的满射双射覆盖，不可虚增已开封计数。
5. **长周期谱系迭代验证（Multi-Milestone Lineage Chain Integrity）**：
   * 协议原生支持 $M_1 \to M_2 \to M_3 \to \dots \to M_k$ 的长周期推演。
   * 支持两种等价判定形式：递归嵌套前驱凭证判定与显式顺序链迭代判定（`appraise_lineage_chain`）。后继节点必须严格绑定直接前驱目标摘要，且持有前驱治理门限签署的 `LineageTransition`。
6. **已知谱系锚定与平行谱系隔离（Genesis & Predecessor Pinning）**：
   * 仅凭可自选的 `lineage_id` 字符串不足以全局唯一约束谱系。验证器客户端策略支持配置 `expected_genesis_target_digest` 或 `expected_parent_target_digest`。
   * 任何具有相同 `lineage_id` 但源自不同创世目标的平行分叉谱系均被显式拒绝（`REJECTED_GENESIS_DIGEST_MISMATCH`）。
7. **前驱治理一致性与授权闭合（Predecessor Quorum Integrity & Governance Consistency）**：前驱证明本身必须通过自体验证，且前驱治理对象必须与前驱目标中的 `governance_digest` 严格匹配，杜绝治理对象替换与 Fresh-key 劫持。
8. **槽位与公钥单射约束（Slot-Key Non-Duplication）**：治理对象中所有 `slot_id` 必须唯一，且所有槽位的公钥亦必须互不相同。严禁单把私钥通过复用槽位冒充多作者法定门限（Anti-Sybil Quorum）。
9. **防晚期加强回溯（No Retroactive Strengthening）**：在里程碑 $M_2$ 中解除假设的更强结论，**绝不得（MUST NOT）** 挂靠或继承至 $M_1$ 的时间节点。
10. **域隔离抗重放（Domain Separation Invariance）**：开封证明与特定谱系 ID 及里程碑序号强绑定，禁止跨课题、跨节点移植。
11. **真实 RFC 3161 时间凭据验证与 Nonce 绑定（Cryptographic RFC 3161 with Nonce Binding）**：时间戳核验针对标准 DER CMS SignedData 解析，验证 MessageImprint 与签名目标一致、签名在证书有效期内、具备 Time Stamping EKU、匹配受信任签名证书指纹 Pin。当请求 Nonce 存在时核验 `TSTInfo.nonce == expected_nonce`。
    * *工程说明*：若要端到端证明 Nonce 来自最初客户端生成而非事后回填，系统建议归档原始 `TSQ` 请求文件。
12. **时间证据严格语义拆分与非升级约束（Timestamp Semantic Scope Distinction & Anti-Inflation, REG-14）**：
    时间戳断言严格依据其 `imprint_scope` 拆分：
    - 当 `imprint_scope == "target"`：时间戳覆盖整个 `ApprovalTarget` JCS 字节，验证通过后仅输出 `APPROVAL_TARGET_EXISTED_NOT_AFTER(lineage_id, milestone, time)`；
    - 当 `imprint_scope == "archive"`：时间戳仅覆盖 `encrypted_archive_digest`，验证通过后仅输出 `ARCHIVE_DIGEST_EXISTED_NOT_AFTER(archive_digest, time)`。
    - **语义防升级约束**：归档时间戳绝不能（MUST NOT）推出后来构造的 `ApprovalTarget`、治理对象或特定里程碑当时已经存在。DigiCert 离线 fixture 验证的是 RFC 3161 解析器能够复验真实外部回执的 `ARCHIVE_DIGEST_EXISTED_NOT_AFTER`，而非外部 TSA 预先签署了 SRL 目标。
13. **别名冲突绝对拒绝（Alias Conflict Invariance, REG-15）**：
    为兼顾向前演进与兼容性，规范允许诸如 `salt_commitment` / `salted_commitment`、`public_key` / `ed25519_public_key_hex`、`predecessor_target_digest` / `parent_target_digest` 等别名，但**严禁两字段同时出现且值冲突**。出现冲突必须硬性拒绝并输出 `REJECTED_ALIAS_CONFLICT`，禁止静默选一。
14. **深度递归耗尽防御（Recursion Depth Protection, REG-16）**：
    嵌套前驱递归深度上限设定为 32。验证器在前驱解析阶段以 $O(d)$ 指针预检深度，若深度超过 32 直接返回 `REJECTED_MAX_PREDECESSOR_DEPTH_EXCEEDED`，消除深度递归堆栈溢出风险。
15. **非法 Transition 安全拒绝（Safe Transition Object Handling, REG-17）**：
    当 `LineageTransition` 的 domain 或 parent/child 摘要/序号不匹配时，验证器直接追加 `REJECTED_INVALID_TRANSITION_TARGET`，并安全短路签名核验流程，绝不得（MUST NOT）由于变量作用域穿透而抛出 `UnboundLocalError` 或未捕获异常。
16. **公钥别名归一化与统一冲突检测（Unified Public Key Normalization, REG-18）**：
    在治理槽位（`author_slots`）、普通里程碑签名（`signatures`）、前驱槽位（`pred_slots`）以及前驱授权签名（`transition.signatures`）四个位置，统一使用 `extract_normalized_ed25519_pubkey`。支持单提供 `ed25519_public_key_hex` 的仅别名对象（杜绝 `KeyError`），同时对混用且值不符的对象坚决拒绝并输出 `REJECTED_ALIAS_CONFLICT`。
17. **扁平化 O(1) 栈长链迭代与诊断字符串有界化（Flat Iterative Chain & Bounded Diagnostics, REG-19）**：
    `appraise_lineage_chain` 采用扁平迭代架构：每个已验证里程碑生成只包含必要验证事实的轻量凭证（`target`, `governance`, `target_digest`, `genesis_target_digest`），传入后继判定时直接标记 `predecessor_verified=True`，彻底杜绝多层链逐级重复递归祖先的问题，实现在 $O(1)$ 栈空间下验证任意长度（实测 35 节全通过）。同时，前驱失败诊断信息严格截断至单行主要错误代码，消除多层错误信息指数级膨胀（从 ~603 MB 降至 < 300 字节）。
18. **输入全态安全解析（Input Totality & Safe Hex/Digest Parsing, REG-20）**：
    所有外部不可信字段中的十六进制与摘要（`catalog_root`、`predecessor_digest`、`encrypted_archive_digest`、`salt`、`salt_commitment`、`tsr_der_hex` 等）均由 `safe_parse_sha256_hex` 与 `safe_parse_hex` 安全解析，长度异常或非十六进制字符统一转换为类型化拒绝（`REJECTED_MALFORMED_HEX`、`REJECTED_INVALID_DIGEST_LENGTH`），保证验证器在面对任何畸形恶意输入字典时维持全态（Totality），绝不抛出未经处理的 Python `ValueError`。
19. **空集合与非结构化输入完全容错（Collection Nullability & Structural Robustness, REG-21）**：
    针对未提供集合键或提供 `None`、标量字符串而非列表的恶意对象（`signatures: null`、`opened_claims: null`、`chain: "str"`、`audit_path: null` 等），验证器全面进行类型预检与安全提取，杜绝 `TypeError: 'NoneType' object is not iterable` 与 `AttributeError` 崩溃。
20. **RFC 8785 规范 JSON 严格全态解析（RFC 8785 Safe Serialization & Float/Unsafe Integer Trapping, REG-22）**：
    验证器核心引入 `safe_canonical_json_dumps` 与 `safe_compute_leaf_hash`，将浮点数（`float`）、不安全大整数（`> 2^53 - 1`）以及未定义 JSON 对象的序列化异常安全捕获并封装为类型化拒绝（`REJECTED_NON_CANONICAL_JSON`），绝不向调用栈抛出底层未受控的 `ValueError: FLOAT_FORBIDDEN`。
21. **里程碑序号强类型与创世不变量（Milestone Index Strict Bounds & Genesis Invariants, REG-23）**：
    严格校验 `milestone_index` 必须为 $\ge 1$ 整数。$M_1$ 创世里程碑绝对禁止声明前驱摘要（`REJECTED_GENESIS_HAS_PREDECESSOR`），$M > 1$ 里程碑强制要求非空前驱摘要（`REJECTED_MISSING_PREDECESSOR_DIGEST`），防止篡改序号导致的非法创世挂接与条件旁路。
22. **Merkle 目录规模边界与常数内存防 DOS（Bounded Leaf Count & O(1) Memory Verification, REG-24）**：
    强制约束 `catalog_leaf_count \le 65536`。开封覆盖完整性核验由原本的 `set(range(N))` 升级为基于鸽巢原理的双射判定（$O(1)$ 额外堆内存），杜绝恶意构造巨额叶片声明（如 $10^{18}$ 或超限值）引发的内存耗尽与 OOM 拒绝服务攻击。

### 1.2 明确排除的非声明（Explicit Non-Claims）

验证器**绝不证明（MUST NOT Infer）**：
* 现实自然人身份与法律非否认性（除非配合外部真实身份公证体系）；
* 形式化推导或自然语言表述在客观世界数学上的真理性（除非外接可信定理证明器内核）；
* 对终局目标定理的独占优先权或知识产权；
* 后来独立完成者是否构成学术抄袭或衍生剽窃；
* 密封者当时是否具有全局洞察力。

---

## 2. 规范化数据对象与协议格式

系统内部计算一律采用 **SHA-256**，结构化 JSON 编码一律遵循 **RFC 8785 (JCS)** 规范化字节序。

### 2.1 声明目录项 (`ClaimCatalogItem`)

每个细粒度学术声明（引理、猜想、反例、计算步骤等）必须独立存在于声明目录中：

```json
{
  "claim_id": "CLM-001",
  "statement_summary": "Lemma L holds under Compactness Condition A",
  "claim_status": "CONDITIONALLY_PROVED",
  "assumptions": ["ASSUMP-A-COMPACTNESS"],
  "proof_obligations_open": ["REMOVE-ASSUMP-A"],
  "salt_commitment": "sha256:e1b7a2bb00000000000000000000000000000000000000000000000000000000"
}
```

* `claim_status` **必须（MUST）** 为以下有限枚举状态之一：
  `CONJECTURED` | `CONDITIONALLY_PROVED` | `UNCONDITIONALLY_PROVED` | `DISPROVED` | `ABANDONED`
* `assumptions` 与 `proof_obligations_open` **必须（MUST）** 在序列化时按字典序严格升序排列。
* `salt_commitment` **必须（MUST）** 为高熵加盐承诺：$\text{SHA-256}(salt \parallel material\_bytes)$，其中 $salt$ 至少包含 32 字节。为保证向后兼容，实现可同时接受 `salted_commitment` 别名。

### 2.2 域隔离 Merkle 树与拓扑位置推导（RFC 6962 风格）

树哈希计算**必须（MUST）** 包含域隔离前缀字节：

$$\text{Leaf}_i = \text{SHA-256}(\text{"SRL:LEAF:v1\x00"} \parallel \text{JCS}(\langle \text{lineage\_id}, \text{milestone\_index}, \text{item}_i \rangle))$$
$$\text{Node}(L, R) = \text{SHA-256}(\text{"SRL:NODE:v1\x00"} \parallel L \parallel R)$$

**拓扑方向推导法则**：
设当前层节点总宽度为 $W$，当前考察节点的索引为 $idx$（$0 \le idx < W$）：
1. 若 $idx \pmod 2 = 0$：
   * 若 $idx + 1 < W$：其右侧必有兄弟节点，期望方向为 `"right"`，兄弟哈希位于路径下一个位置；
   * 若 $idx + 1 = W$：该节点为奇数末尾孤立节点，不与任何兄弟哈希配对，直接提升至上一层，不消耗路径步数。
2. 若 $idx \pmod 2 = 1$：
   * 其左侧必有兄弟节点，期望方向为 `"left"`，兄弟哈希位于路径下一个位置。
3. 每一层迭代后，新位置 $idx \leftarrow \lfloor idx / 2 \rfloor$，新层宽 $W \leftarrow \lfloor (W + 1) / 2 \rfloor$。直到 $W = 1$ 达到树根。

### 2.3 治理结构 (`Governance`)

管理里程碑签署权与前驱过渡权的授权门限：

```json
{
  "threshold": 2,
  "author_slots": [
    {
      "slot_id": "slot-01-lead",
      "public_key": "ed25519:4a5b6c0000000000000000000000000000000000000000000000000000000000"
    },
    {
      "slot_id": "slot-02-coauthor",
      "public_key": "ed25519:7d8e9f0000000000000000000000000000000000000000000000000000000000"
    }
  ]
}
```

* **门限合法性**：$1 \le threshold \le len(author\_slots)$。禁止 $threshold = 0$ 或空作者列表。
* **唯一性不变量**：所有 `slot_id` 必须唯一；所有 `public_key` 必须唯一。实现兼容支持 `ed25519_public_key_hex` 别名字段。

### 2.4 批准目标对象 (`ApprovalTarget`)

多作者签署和时间戳绑定的核心闭合对象：

```json
{
  "domain": "SRL:APPROVAL_TARGET:v1",
  "lineage_id": "srl:lin:riemann-gap-demo",
  "milestone_index": 1,
  "catalog_leaf_count": 2,
  "predecessor_digest": null,
  "catalog_root": "sha256:5555555555555555555555555555555555555555555555555555555555555555",
  "encrypted_archive_digest": "sha256:6666666666666666666666666666666666666666666666666666666666666666",
  "governance_digest": "sha256:7777777777777777777777777777777777777777777777777777777777777777"
}
```

* `catalog_leaf_count` **必须（MUST）** 显式包含于 `ApprovalTarget` 中并接受作者签名保护，防止攻击者篡改自报叶子总数冒充完整开封。
* `governance_digest` **必须（MUST）** 为 `Governance` 对象的规范化 JCS 序列化的 SHA-256 摘要。

### 2.5 谱系过渡授权对象 (`LineageTransition`)

当从前驱里程碑演化至当前里程碑时，用于证明后继谱系承袭合法性：

```json
{
  "domain": "SRL:LINEAGE_TRANSITION:v1",
  "lineage_id": "srl:lin:riemann-gap-demo",
  "predecessor_target_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
  "successor_target_digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
  "predecessor_milestone_index": 1,
  "successor_milestone_index": 2
}
```

* 规范统一命名为 `predecessor_target_digest`、`successor_target_digest`、`predecessor_milestone_index`、`successor_milestone_index`。为兼容既有代码，实现层同时支持 `parent_target_digest`、`child_target_digest`、`parent_milestone_index`、`child_milestone_index`。
* 该对象必须获得前驱节点 `Governance` 所规定法定门限的签名支持。

### 2.6 外部时间戳凭据 (`TimestampSidecar`)

提供符合 RFC 3161 规范的外部可信时间证据：

```json
{
  "format": "RFC3161_DER",
  "tsr_der_hex": "3082...",
  "expected_nonce": 987654321,
  "imprint_scope": "target"
}
```

* `imprint_scope` 可为 `"target"`（默认，核验证书 imprint 匹配 `SHA-256(JCS(ApprovalTarget))`）或 `"archive"`（核验证书 imprint 匹配 `target.encrypted_archive_digest`）。
* **验证要求**：解析真实 DER CMS 封装，核验 RFC 3161 `TSTInfo`、时间戳扩展密钥用法（Time Stamping EKU）、证书生失效期、外部 Pin 证书指纹一致性以及请求 Nonce 一致性。

---

## 3. 验证器判定推导法则（Normative Appraisal Rules）

验证输入为开封证明 $\Pi = \langle Target, Governance, Signatures, TimestampToken, PredecessorProof, Transition, TransitionSignatures, OpenedClaims \rangle$ 及外部策略 $\mathcal{P}$。

### 规则 1：门限签名合法性（Quorum Satisfaction）
$$\frac{
  \begin{aligned}
  threshold \ge 1 \quad len(author\_slots) \ge threshold \\
  \text{UniqueSlots}(Signatures) \quad \text{UniqueKeys}(Signatures) \\
  \text{ValidEd25519}(Target, Signatures) \ge threshold \quad Signers \subseteq author\_slots
  \end{aligned}
}{\Pi \vdash \text{AUTHORIZED\_MILESTONE\_TARGET}}$$

### 规则 2：前驱治理与过渡闭合（Predecessor Quorum & Governance Consistency）
当 $Target.predecessor\_digest \neq null$ 时：
$$\frac{
  \begin{aligned}
  \text{Appraise}(PredecessorProof) = \text{PASS} \\
  \text{SHA-256}(\text{JCS}(PredecessorProof.target)) = Target.predecessor\_digest \\
  \text{SHA-256}(\text{JCS}(PredecessorProof.governance)) = PredecessorProof.target.governance\_digest \\
  \text{ValidPredecessorSignatures}(Transition, PredecessorGov) \ge PredecessorGov.threshold
  \end{aligned}
}{\Pi \vdash \text{AUTHORIZED\_PREDECESSOR\_TRANSITION}}$$

### 规则 3：真实时间戳核验与语义非升级拆分（Cryptographic Timestamp Verification & Scope Split）
依据 `Token.imprint_scope` 严格分流判定：

1. **目标时间戳（Target Imprint Scope）**：
$$\frac{
  \begin{aligned}
  Token.imprint\_scope = \text{"target"} \\
  \text{VerifyTSR}(Token.tsr\_der, \text{SHA-256}(\text{JCS}(Target)), Pin, Token.expected\_nonce) = \text{Granted}(T_k)
  \end{aligned}
}{\Pi \vdash \text{APPROVAL\_TARGET\_EXISTED\_NOT\_AFTER}(lineage\_id, milestone\_index, T_k)}$$

2. **归档时间戳（Archive Imprint Scope）**：
$$\frac{
  \begin{aligned}
  Token.imprint\_scope = \text{"archive"} \\
  \text{VerifyTSR}(Token.tsr\_der, Target.encrypted\_archive\_digest, Pin, Token.expected\_nonce) = \text{Granted}(T_k)
  \end{aligned}
}{\Pi \vdash \text{ARCHIVE\_DIGEST\_EXISTED\_NOT\_AFTER}(Target.encrypted\_archive\_digest, T_k)}$$

* **语义防升级约束（REG-14）**：归档时间戳在证明体系中**绝不可（MUST NOT）** 升级为 `APPROVAL_TARGET_EXISTED_NOT_AFTER`。

### 规则 4：单项声明开封真值（Claim Truth Extraction）
$$\frac{
  \begin{aligned}
  \Pi \vdash \text{AUTHORIZED\_MILESTONE\_TARGET} \\
  \text{SHA-256}(Salt_i \parallel Content_i) = Item_i.salt\_commitment \\
  \text{VerifyDerivedMerklePath}(Leaf_i, AuditPath_i, Target.catalog\_root, LeafIndex_i, Target.catalog\_leaf\_count) = \text{TRUE} \\
  0 \le LeafIndex_i < Target.catalog\_leaf\_count
  \end{aligned}
}{\Pi \vdash \text{EXACT\_CLAIM\_OPENING\_VERIFIED}(Item_i.claim\_id, Item_i.claim\_status, Item_i.assumptions)}$$

### 规则 5：防晚期加强隔离约束（Anti-Strengthening Invariant）
若 $Item_i.claim\_status = \text{UNCONDITIONALLY_PROVED}$ 且 $Item_i.assumptions \neq \emptyset$，验证器**必须（MUST）** 拒绝并输出：
$$\text{REJECTED\_ASSUMPTION\_MUTATION}$$

### 规则 6：开封作用域非放大与防重开封约束（Scope Non-Amplification & Anti-Duplication）
设验证通过的开封项索引集合为 $S = \{ LeafIndex_i \}$，声明 ID 集合为 $C = \{ ClaimId_i \}$，叶哈希集合为 $H = \{ LeafHash_i \}$，目标固化的总叶子数为 $N = Target.catalog\_leaf\_count$：
1. 若开封过程中发现重复叶索引（$LeafIndex_i \in S$），验证器立即拒绝并输出 `REJECTED_DUPLICATE_OPENED_LEAF`。
2. 若发现重复声明 ID（$ClaimId_i \in C$），验证器立即拒绝并输出 `REJECTED_DUPLICATE_CLAIM_ID`。
3. 若发现相同叶哈希被提交在不同位置（$LeafHash_i \in H$），验证器立即拒绝并输出 `REJECTED_DUPLICATE_LEAF_HASH`。
4. 仅当 $S = \{0, 1, \dots, N-1\}$ 且 $|C| = N$ 且 $|H| = N$ 时，验证器方可输出：
   $$\text{COMPLETE\_CATALOG\_OPENING}(N)$$
5. 若 $S \subset \{0, \dots, N-1\}$ 且证明声称完整开封，验证器**必须（MUST）** 拒绝并输出 `REJECTED_SCOPE_AMPLIFICATION`。

### 规则 7：终局功劳不可推导（Terminal-Credit Prohibition）
对于任何包含“是否属于首发”、“后来者是否抄袭”等终局功劳判定查询，验证器**必须（MUST）** 终止判定并返回：
$$\text{REFUSED: TERMINAL\_CREDIT\_NON\_EVALUABLE}$$

### 规则 8：别名冲突绝对拒绝（Alias Conflict Invariant, REG-15）
若输入对象同时包含规范字段及其兼容别名字段（如 `salt_commitment` 与 `salted_commitment`、`public_key` 与 `ed25519_public_key_hex`、`predecessor_target_digest` 与 `parent_target_digest` 等）且两字段取值冲突，验证器**必须（MUST）** 拒绝并输出：
$$\text{REJECTED\_ALIAS\_CONFLICT}$$

### 规则 9：前驱递归深度保护（Max Predecessor Depth Bound, REG-16）
递归嵌套前驱证明的调用深度不得超过 $\text{MAX\_DEPTH} = 32$。若 $\text{depth} \ge 32$，验证器**必须（MUST）** 终止递归并输出：
$$\text{REJECTED\_MAX\_PREDECESSOR\_DEPTH\_EXCEEDED}$$

### 规则 10：非法 Transition 边界隔离（Safe Transition Handling, REG-17）
若 `LineageTransition` 的域隔离前缀不符（非 `SRL:LINEAGE_TRANSITION:v1`）或目标摘要不匹配，验证器**必须（MUST）** 立即记录：
$$\text{REJECTED\_INVALID\_TRANSITION\_TARGET}$$
且**严禁（MUST NOT）** 继续引用未初始化的规范化字节导致 `UnboundLocalError` 或未捕获异常。

### 规则 11：统一公钥别名与单射约束（Unified Key Normalization, REG-18）
验证器在解析 `author_slots`、`signatures`、`pred_slots` 与 `transition.signatures` 时，**必须（MUST）** 统一经由归一化流程检验：
1. 允许仅含 `ed25519_public_key_hex` 的兼容输入；
2. 若同时存在规范名与别名但取值不一致，**必须（MUST）** 拒绝并输出 `REJECTED_ALIAS_CONFLICT`；
3. 提取出的公钥必须严格为 32 字节（64 字符十六进制）。

### 规则 12：顺序迭代链 O(1) 栈与有界诊断（Flat Chain & Bounded Diagnostics, REG-19）
`appraise_lineage_chain` 验证序列 $[M_1, M_2, \dots, M_k]$ 时：
1. 验证通过的 $M_{i-1}$ 以扁平凭据形式注入 $M_i$，前驱标志设为 `predecessor_verified=True`，验证过程在栈空间复杂度上**必须维持（MUST Maintain）$O(1)$**；
2. 任何下层失败传播时，**必须（MUST）** 将诊断字符串严格截断至顶层错误码与发生深度，严禁将全量递归列表字符串循环嵌套。

### 规则 13：输入全态安全解析（Input Totality & Safe Hex/Digest Parsing, REG-20）
对任意未经清洗的外部输入字段（摘要、盐、公钥、TSR 字节等）：
1. 长度不符或含非十六进制字符时，验证器**必须（MUST）** 转化为类型化拒绝（如 `REJECTED_MALFORMED_HEX`、`REJECTED_INVALID_DIGEST_LENGTH`）；
2. 验证器对外暴露的评估入口**绝不能（MUST NOT）** 抛出未经捕获的 Python `ValueError`、`KeyError` 等内部异常。

---

## 4. 与 ACSD 公开发表生命周期的工程衔接（Publication Crosswalk）

当研究团队完成阶段性秘密推演并准备公开发表时，SRL 与现有 ACSD 体系通过跨阶段侧信道形成可验证链路：

```text
 [秘密阶段: SRL Profile]
   M1 (封存 L1, L2) ──[前驱授权]──> M2 (封存 L1~L9) ──[前驱授权]──> M3 (收敛定理 T)
           │                                │                              │
           ▼ (部分开封 L1)                   ▼ (部分开封 L1~L5)              ▼ (完全开封 T)
   OpenProof(M1, L1)                OpenProof(M2, L1~L5)           OpenProof(M3, T)
                                                                           │
 ──────────────────────────────────────────────────────────────────────────┼─
 [公开阶段: ACSD Core & Submission-Link]                                  │
                                                                           ▼
                                                                   ACSD Release v1.0.0
                                                               (附带 LineageCrosswalkSidecar)
                                                                           │
                                                                           ▼
                                                                   Conference / Journal
                                                               (Submission-Link Challenge)
```

1. **谱系过渡侧信道 (`lineage_crosswalk.json`)**：
   公开的 `PaperRelease` 在其 `PEC` 承诺中，将最后一个密封里程碑 $M_k$ 的 `ApprovalTarget` 哈希作为前驱输入，建立从密封推演到公开版本的确定性映射。
2. **投稿绑定（Submission-Link）**：
   结合 ACSD v4.0.0-rc2 已实现的 `submission-link` 机制，将密封历史与期刊会议的匿名审稿盲审凭证挂钩，为审稿人和编辑部提供不可篡改的时间与版本演化审计凭证。
