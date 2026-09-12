# GPT 评估与分工（存档）

> 记录时间：2026-09-12。来源：用户转发的 GPT 意见。本文件仅存档，供后续
> 编码阶段对照。

## GPT 的工作量评估

- 距"作者开箱即用的 CLI MVP"：还差当前项目的 **25%–35%** 工程量。
- 距"放心给陌生用户使用的稳定产品"：还差约 **一倍** 工作量。
- 分项估计：
  - 单作者、本地签名、生成/验证发布包：**1–2 个集中工作日**。
  - 多作者分阶段审批、真实 RFC 3161、可靠错误处理：再加 **2–4 天**。
  - Windows/Linux/macOS 安装包、CI、跨平台实测和文档：再加 **3–7 天**。
  - 真正稳定的 v1.0 CLI：约 **1–2 周** 集中开发。

## GPT 提出的目标界面

```powershell
acsd init paper.pdf --team team.json
acsd approve release-dir --key author-key
acsd finalize release-dir --tsa https://...
acsd verify release-dir
acsd release paper.pdf --team team.json --key author-key --tsa https://...  # 单作者快捷
```

设计原则：单作者一行命令；多作者三阶段（因为多作者必须各自控制自己的私钥）。

## GPT 列出的六块缺口

1. 协议硬伤：`ensure_ascii` 不一致（**已修，commit b882149**）、明确 Unicode
   canonicalization、跨实现 Unicode 回归测试、真实 PDF 摘要替换 demo 占位符。
2. CLI 外壳：argparse 零额外依赖入口、init/approve/finalize/verify/inspect、
   机器可读 JSON 输出与退出码、先写临时目录再原子生成。
3. 密钥与多人工作流：默认 Ed25519、私钥绝不进包、跨机器审批、finalize 检查
   全部签名、密钥轮换/撤销说明。
4. 真实时间戳：`finalize --tsa` 只发 SHA-256 imprint、保存 tsq/tsr/证书链/
   报告、TSA 不可用时允许显式降级、verify 离线验证。
5. 发布包与复现：从真实论文生成对象、完整 manifest、清除临时文件/绝对路径/
   身份泄漏、全新目录复验、Node verifier 打包或 pin 版本。
6. 产品层：pipx/单文件安装、PS1/bash 入口、三平台 CI、Quickstart、友好错误。

## GPT 提议的分工

- **DeepSeek**：规范审查、测试向量、CLI 状态机、攻击清单。
- **GPT/作者**：最终架构裁决、实际编码、密码学边界、多人签名、
  RFC 3161 集成、全套复验、论文同步。

## DeepSeek 的交付（本目录 `design/`）

- `CANONICAL-SPEC.md` —— 逐字节规范、64 向量差分实测、五处分歧裁决、补丁
  建议 P1–P5（**注意：实测推翻了审稿意见 1.2 中"Python/JS 在 `\b`/`\f` 上
  分歧"的推测，三者一致**）。
- `canonical_diff_runner.py` + `canonical_ref.cjs` + `canonical_diff_vectors.json`
  + `canonical_diff_report.json` —— 可复现的差分测试资产。
- `CLI-SPEC.md` —— 命令接口、目录结构、状态机、退出码、JSON 输出、原子性、
  密钥工作流、RFC 3161、跨平台、声明边界。
- `CLI-TEST-MATRIX.md` —— 45 个测试 case（M=必须自动化）。
- `ATTACK-MISUSE.md` —— 20 项攻击/误用与防护。
- `IMPLEMENTATION-NOTES.md` —— 模块拆分、可复用 vs 重写判断、架构决策点。
