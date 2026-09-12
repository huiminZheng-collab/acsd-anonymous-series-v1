# CLI 测试矩阵（accompanying CLI-SPEC.md v0.1）

> 任务 B 交付物。每个 case：ID / 命令序列 / 前置 / 期望结果与退出码。
> "M" = 必须自动化（CI）；"O" = 可选（手工/后续）。

## 1. init

| ID | 场景 | 期望 |
|---|---|---|
| M-INIT-01 | 单作者正常 init | state=`awaiting-approvals`；release digest 稳定；exit 0 |
| M-INIT-02 | 同一 PDF+team 重跑 | **幂等**：同一 release digest、不重复创建 |
| M-INIT-03 | PDF 不存在 / 不可读 | exit 2，无目录残留 |
| M-INIT-04 | team.json 缺 schema / 作者为空 | exit 2，`TEAM_INVALID` |
| M-INIT-05 | team 里 key_id 非 sha256 格式 | exit 2 |
| M-INIT-06 | `--work-id` 非 UUID 格式 | exit 2 |
| M-INIT-07 | PDF 为 0 字节 | exit 2（拒绝空内容） |
| M-INIT-08 | `--out` 指向已存在的非空目录 | exit 3（不覆盖） |
| O-INIT-09 | 中文文件名 PDF（Windows/macOS/Linux） | 正常，包内文件名是 `<sha256>.pdf`（无原始文件名泄漏） |

## 2. approve

| ID | 场景 | 期望 |
|---|---|---|
| M-APP-01 | 正确私钥 approve | exit 0；签名出现在 approvals/，payload 是共同 approval target |
| M-APP-02 | 错误私钥（不在 team） | exit 1 `UNKNOWN_AUTHOR_KEY` |
| M-APP-03 | 同一 key 重复 approve | exit 3 `DUPLICATE_APPROVAL` |
| M-APP-04 | 私钥无法解析 / 口令错 | exit 2 |
| M-APP-05 | 对 `finalized` 目录 approve | exit 3 `STATE_CONFLICT` |
| M-APP-06 | approve 后篡改 release/governance/PEC 再 approve | 立即拒绝 `APPROVAL_TARGET_BINDING_MISMATCH`；不得形成混合批准集 |
| M-APP-07 | 两作者乱序 approve（B 先 A 后） | 都成功；finalize 只要求集合齐全（顺序无关） |
| O-APP-08 | 私钥文件在 release-dir 内被 approve 命令读 | **拒绝**：CLI 拒绝读取 release-dir 内的 key 文件（防私钥入包） |

## 3. finalize

| ID | 场景 | 期望 |
|---|---|---|
| M-FIN-01 | 签名齐全 + TSA 成功 | exit 0；state=`finalized`；manifest 覆盖全部文件 |
| M-FIN-02 | 缺 1/N 签名 | exit 5 `APPROVALS_INCOMPLETE`；输出 missing_keys |
| M-FIN-03 | TSA 不可达，无 --allow-untimestamped | exit 4；状态回退 awaiting-approvals；已有 approval 保留 |
| M-FIN-04 | TSA 不可达 + --allow-untimestamped | exit 0；state=`finalized-untimestamped`；输出显著标注 DEGRADED |
| M-FIN-05 | TSA 返回错误 imprint 的 tsr | exit 1（响应绑定失败），不产生 finalized |
| M-FIN-06 | finalize 中途断电/崩溃 | staging 残留被下次运行清理；release-dir 仍是 awaiting-approvals 或完整 finalized（无第三态） |
| M-FIN-07 | 对已 finalized 再 finalize | exit 3 `STATE_CONFLICT` |
| M-FIN-08 | 对已 finalized 或 finalized-untimestamped 再 finalize | exit 3；发布版本只增不改 |
| M-FIN-09 | 签名齐全但 PEC 组装时 canonical 失败（含 lone surrogate 等） | exit 1，不留 staging |

## 4. verify

| ID | 场景 | 期望 |
|---|---|---|
| M-VER-01 | 完整 finalized 目录 | `VALID`；granted outcomes + non-claims 同时输出；exit 0 |
| M-VER-02 | 篡改 paper PDF 一个字节 | `TAMPERED`；exit 1 |
| M-VER-03 | 篡改 manifest 中任一文件的任一字节 | `TAMPERED`；exit 1 |
| M-VER-04 | 删除一个文件（manifest 多出条目） | `TAMPERED`；exit 1 |
| M-VER-05 | 塞入 manifest 未列的文件 | `TAMPERED`（MANIFEST_SET_MISMATCH 语义）；exit 1 |
| M-VER-06 | 从全新目录（无任何依赖）verify | 同样结果（离线、零外部依赖） |
| M-VER-07 | 合法 finalized-untimestamped | 作者批准仍可 `VALID`；不输出 EXTERNALLY_NOT_AFTER |
| M-VER-08 | 带 TSA 回执且验证者给出外部 signer cert/fingerprint pin | 验证 tsq/tsr/nonce/profile/genTime 后输出 `EXTERNALLY_NOT_AFTER`；不输出创作时间类声明 |
| M-VER-09 | TSA 回执被换（另一个 tsr） | exit 1 `RECEIPT_SUBJECT_MISMATCH` |
| M-VER-10 | awaiting-approvals 中间态目录 | `INCOMPLETE`；列出缺的 key；exit 5 |
| M-VER-11 | 非 canonical JSON 的 release.json（键乱序） | `TAMPERED`/`PEC_NONCANONICAL`；exit 1 |
| M-VER-12 | release.json 含重复键 | 拒绝（字节对比）；exit 1 |
| M-VER-13 | 路径穿越文件名（manifest 或包内 `..`） | exit 1 `MANIFEST_PATH_INVALID`，且 verify 不读包外文件 |

## 5. inspect / 杂项

| ID | 场景 | 期望 |
|---|---|---|
| M-INS-01 | inspect 各状态目录 | 输出 state / 缺签名列表 / WorkID / digest / TSA 状态；只读（mtime 不变） |
| M-REL-01 | 单作者 `acsd release` 一条龙 | 等价 init+approve+finalize；exit 0 |
| M-REL-02 | 多个 `--key` 用 `acsd release` | 所有私钥在本机时一条龙成功；分布式团队使用分步流程 |
| M-CL-01 | 未知子命令 / 未知选项 | exit 2，usage 到 stderr |
| M-CL-02 | `--json` 输出是合法单行 JSON；人类模式是易读文本 | 结构断言 |
| M-CL-03 | 三平台（CI：Windows/macOS/Linux）全矩阵通过 | 行尾、路径、权限（0600）断言 |

## 6. 回归链接

- 差分 canonical 测试（`design/canonical_diff_runner.py`）作为
  M-VER-11/12 的底层依赖，CI 中必须先跑且 exit 0。
- 当前 v2 unittest（51 pass + 1 个网络测试离线 skip）、1,000 个生成式
  差分样本与 demo/v1 复验保持通过。
