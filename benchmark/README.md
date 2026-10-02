# 测评数据集

这个目录放的是面板「数据集测评」页读的数据集：只有元数据（JSONL），不含上游仓库的代码。
上游项目在测评时按每组记录里的 `repo_url` + commit 现拉，和函数检测走同一条检出流程。

每个子目录是一份数据集，`web/server/evaluation.py` 的 `DATASET_SPECS` 里登记一份就能在页面上选到。
约定是 `<id>/<名字>.jsonl` 加一份可选的 `_manifest.json`；`EVAL_DATASET_ROOT` 可以改这个根目录
（`scripts/verify_evaluation.py` 就是靠它把数据集指向临时目录来跑离线测试）。

## drea — RepoPairBench 100

- `drea/repopairbench_100.jsonl` — 100 组漏洞修复对
- `drea/repopairbench_100_manifest.json` — 同一批的补充信息（修复 commit message、`commit_url` 等）

来源是 DREA 论文的公开产出（*DREA: Decoupled Reasoning and Exploration Agents for
Repository-Level Vulnerability Detection*，Internetware '26，Sun & Meng）：

> Sun, Mingyang and Meng, Guozhu. *DREA: Decoupled Reasoning and Exploration Agents for
> Repository-Level Vulnerability Detection.* Proceedings of the 17th International Conference
> on Internetware (Internetware '26), Gold Coast, Australia, 2026.

RepoPairBench 100 收集了 2021–2025 年 NVD 里 CVE 关联的 Python 修复提交，用 PyDriller 抽出函数级
diff，过滤掉新增/删除文件和新引入的函数，只保留修复前后能干净对齐的函数对。覆盖 48 个 CWE，
出现最多的五类是 CWE-79（13）、CWE-22（10）、CWE-20（7）、CWE-502（7）、CWE-94（7）。

每一行 JSON 的字段（`web/server/evaluation.py` 的 `DatasetItem` 读的就是这些）：

| 字段 | 说明 |
| --- | --- |
| `id` | 样例 id（8 位十六进制） |
| `project_name` | 上游项目名 |
| `repo_url` | 公开仓库地址 |
| `commit_hash` | **修复**提交 |
| `language` | 语言标签（全部是 `python`） |
| `cve_ids` / `cwe_ids` | 关联的 CVE / CWE |
| `vuln_data.file_path` | 目标文件在仓库里的路径 |
| `vuln_data.code_before` | 修复**前**的目标函数（取自 `commit_hash` 的父提交） |
| `vuln_data.code_after` | 修复**后**的目标函数（取自 `commit_hash` 本身） |

manifest 里的 `item_id` 就是 JSONL 里的 `id`，按它对上；它额外带了 `commit_message` 和
`commit_url`，页面上用于展示。

> 这份数据只用于研究评测。检出上游仓库时请遵守各项目自己的许可证；这些仓库的代码不在本仓库里。
