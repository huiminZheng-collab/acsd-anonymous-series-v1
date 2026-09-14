# 攻击与误用清单（CLI 落地前评审用）

> 任务 B 交付物。每项：攻击/误用 → 当前防护或缺口 → 建议。用于 GPT/作者
> 在"实际编码"阶段的对抗性自查。按风险排序。

## A. 密码学与协议层

1. **私钥进入发布包**（最严重）
   - 缺口：若 approve 实现为"复制 key 文件到 release-dir 再签名"，私钥会被
     manifest 收录并分发。
   - 防护：approve 只读私钥内存签名；CI 加断言"发布包内无 PEM/seed"。
2. **签名预言机 / 自动签署恶意内容**
   - 误用：脚本把 approve 接进 CI 自动签任何输入。
   - 防护：CLI 不提供"管道输入自动签"模式；approve 要求显式 release-dir 与
     交互确认（`--yes` 才跳过）。
3. **nonce 复用（RFC 3161 请求）**
   - 缺口：nonce 弱或复用 → TSA 响应被猜测/重放。
   - 防护：nonce = `secrets.token_bytes(16)`，`report.json` 记录 nonce 供验证。
4. **TSA 回执重放到新版本**（已有防护，保留）
   - `pec_digest` 不同 → `RECEIPT_SUBJECT_MISMATCH`。不得实现"回执对旧 PEC
     也放行"的兼容路径。
5. **canonical 漂移导致签名失效**
   - 缺口：Python/Node 不一致处（见 CANONICAL-SPEC.md D4/D5）。
   - 防护：CI 差分测试强制两边字节一致；P1/P2/P3 补丁落地。
6. **哈希截断/大小写混淆**
   - 误用：digest 用大写 hex、截断比较、`==` 字符串比较（时序）。
   - 防护：全小写 64 hex；比较用 `hmac.compare_digest` 或 bytes 相等。
7. **大文件 DoS**
   - 误用：`init` 接受任意大小 PDF → 内存/磁盘耗尽。
   - 防护：默认上限（如 64 MiB）可配；分块哈希。

## B. 状态机与一致性层

8. **"看似完整"的半成品包**
   - 缺口：finalize 非原子 → 用户发布不完整目录。
   - 防护：staging + rename；verify 对中间态报 `INCOMPLETE` 而非静默通过。
9. **状态文件与内容不同步**
   - 攻击：手工改 state.json 为 finalized，但 manifest 没生成。
   - 防护：verify 以 manifest+签名为准，**不信任 state.json**；state.json
     只是提示。
10. **TOCTOU**（检查与使用之间的文件替换）
    - 攻击：verify 先验证后读取间替换文件。
    - 防护：单次 pass 内"读字节 → 哈希 → 比较"，读两次并断言一致，或
      先全量加载到内存。
11. **路径穿越**（manifest 条目 `../../evil`、Windows 盘符、UNC 路径）
    - 防护：manifest 解析拒绝绝对路径与 `..` 分量（v1 已有）；CLI 复用并
      加 Windows 特定断言。
12. **符号链接逃逸**（Linux/macOS：release-dir 内 symlink 指向包外）
    - 防护：verify/finalize 拒绝 symlink（`os.path.islink` 检查），包内只
      允许常规文件。

## C. 元数据与身份层

13. **本地时钟当作时间证据**（产品级误用，最高频）
    - 误用：README 或输出暗示"finalize 时间 = 创作时间"。
    - 防护：non-claims 五元组强制出现在所有输出；文档措辞审计
      （CLI-SPEC §10）。
14. **仓库账户/网络/公钥链接性被误认为匿名**
    - 误用：宣称"匿名发布"而忽略托管账户、IP、密钥复用链接。
    - 防护：README 显著声明 content-anonymous ≠ author-unlinkable。
15. **元数据泄漏**（PDF 元数据、临时文件路径、用户名、环境变量）
    - 缺口：`init` 若把原始文件名、绝对路径写入 release.json。
    - 防护：包内只存 `<sha256>.pdf` 与相对路径；CI 扫描包内二进制禁
      止本机用户名与 `C:\`、`/Users/` 等模式。
16. **同一密钥跨多个假身份**（sockpuppet）
    - 限制：ACSD 不解决；只能暴露"同一 key_id 出现在多个 WorkID 的
      governance 里"（`inspect --linkage` 可选功能，仅供人工判断）。

## D. 可用性与社会层

17. **把 KEY_ASSENT 当作者身份**（误读输出）
    - 防护：`--json` 的 data 必须同时含 non-claims；文档示例都展示两者。
18. **TSA 宕机时的错误决策**
    - 误用：自动 `--allow-untimestamped` 并当作有时间证据发布。
    - 防护：降级需显式 flag；state 与输出标注 DEGRADED；无 flag 时 exit 4。
19. **私钥丢失 = 无法轮换**（不可恢复）
    - 防护：keygen 输出时提示备份 seed；文档说明"丢失私钥的 release 无法
      再 approve 新版本"。
20. **审批顺序被当作贡献顺序**
    - 误用：把 endorse 的时间戳顺序解释为署名顺序。
    - 防护：byline 顺序只由 team.json 的 slot 定义；approve 顺序不进包。

## E. 建议的 CI 防线（配合 TEST-MATRIX）

- 差分 canonical 测试（Python vs Node）每 PR 必跑。
- 发布包扫描器：断言包内无 `.pem`/`.key`/`seed`、无绝对路径、无本机用户
  名、无 symlink、manifest 一一对应。
- 三平台矩阵 + `pip install .` / `pipx install` 冒烟测试。
