# DREA 之外的 baseline 候选：论文与官方实现核对

调研日期：2026-10-02。只采用原论文、出版方与作者官方仓库。此次未运行模型、未安装依赖、未执行下载的研究代码；“可复现候选”表示发现了官方实现，不等于已经完成复现。

比较条件由本次主调研提供：DREA 的 RepoPairBench 是 Python 漏洞/修复对，已经给出目标函数。因而应优先比较“给定 Python 函数、可用其真实仓库上下文、独立输出漏洞判断”的方法，再把无种子整仓审计作为额外实验。下文的优先级是针对这一条件的研究判断，不能解释为论文性能排序。

| 候选 | 论文与发表信息 | 实际任务与语言 | 当前匹配程度 | 官方实现 |
|---|---|---|---|---|
| **VulAgent** | *VulAgent: Hypothesis-Validation Driven Multi-Agent Architecture for Vulnerability Detection*，Findings of ACL 2026，2026 年 7 月。[出版页](https://aclanthology.org/2026.findings-acl.928/) | 已给代码单元，多角色发现敏感操作，再用上下文验证条件与触发路径；PrimeVul 是 C/C++，SVEN 包含 C/C++ 与 Python。[论文 §4.1](https://aclanthology.org/2026.findings-acl.928.pdf) | **最值得优先适配**：函数对、Python、上下文验证和多 Agent 都接近；不应描述成从任意整仓无种子发现漏洞 | [HotFrom/VulAgent](https://github.com/HotFrom/VulAgent) |
| **VulnLLM-R** | *VulnLLM-R: Specialized Reasoning LLM with Agent Scaffold for Vulnerability Detection*，2025 年 12 月 arXiv 预印本。[论文](https://arxiv.org/abs/2512.07533) | 专用安全推理模型；官方测试入口接受 Python、C、Java，以及 function_level / repo_level 数据。[官方 README](https://github.com/ucsb-mlsec/VulnLLM-R) | **适合作为专用模型对照**；需区分已公开的分类推理入口与论文完整 Agent scaffold，后者本轮未定位/验证 | [代码](https://github.com/ucsb-mlsec/VulnLLM-R)、[7B 权重](https://huggingface.co/UCSB-SURFI/VulnLLM-R-7B) |
| **VulTrial** | *Let the Trial Begin: A Mock-Court Approach to Vulnerability Detection using LLM-Based Agents*，ICSE 2026；首发 2025 年 5 月。[论文](https://arxiv.org/abs/2505.10961) | 四角色辩论：安全研究者、代码作者、主持人、评审组；主实验给定 PrimeVul 函数对。[论文 v2](https://arxiv.org/html/2505.10961v2) | **次选，多 Agent 推理对照**；原主实验主要是 C/C++，需要在 RepoPairBench 上独立迁移与测试 | 作者给出的 [Figshare 复现包](https://figshare.com/s/1514bc9a7aa64b46d94e)；本轮访问 403，未下载核实 |
| **RepoAudit** | *RepoAudit: An Autonomous LLM-Agent for Repository-Level Code Auditing*，ICML 2025，PMLR 267:21083–21100。[出版页](https://proceedings.mlr.press/v267/guo25n.html) | 按需探索仓库，跨过程数据流推理，路径条件验证，编译无关。[出版方摘要](https://proceedings.mlr.press/v267/guo25n.html) | **整仓审计首选补充**；原生 bug taxonomy 与 Python 注入/鉴权数据不完全一致，需要适配 | [PurCL/RepoAudit](https://github.com/PurCL/RepoAudit) |
| **IRIS** | *IRIS: LLM-Assisted Static Analysis for Detecting Security Vulnerabilities*，ICLR 2025；预印本首发 2024 年 5 月。[正式论文](https://proceedings.iclr.cc/paper_files/paper/2025/file/582d4e27fa24168f3af1f4582655034b-Paper-Conference.pdf) | 输入整 Java 项目与指定 CWE；LLM 推断 source/sink 规范，CodeQL 做全仓污点分析，再由 LLM 排除误报 | **Java 扩展实验候选**；不能直接宣称作者已提供适用于 RepoPairBench 的 Python 版本 | [iris-sast/iris](https://github.com/iris-sast/iris) |
| **LLMxCPG** | *LLMxCPG: Context-Aware Vulnerability Detection Through Code Property Graph-Guided Large Language Models*，USENIX Security 2025，489–507。[出版页](https://www.usenix.org/conference/usenixsecurity25/presentation/lekssays) | CPGQL 查询生成 → Joern 切片 → 专用 LLM 判断；评估函数级和多函数代码。[原论文](https://www.usenix.org/system/files/usenixsecurity25-lekssays.pdf) | **机制对照**，适合比较固定 CPG 切片和按需探索；原文实测重点是内存漏洞，Python 端到端支持本轮未证实 | [qcri/llmxcpg](https://github.com/qcri/llmxcpg) |

## VulAgent：最接近当前 Python 函数对实验

- 正式实验使用已给定函数/代码单元。主流程提出 CWE；只有 §5.5 的验证消融使用 **oracle CWE**，不能把该消融条件误当全部实验条件。[正式论文 §3、§5.5](https://aclanthology.org/2026.findings-acl.928.pdf)
- 官方已有真实 Python context builder：用 `ast.parse` 提取目标函数中的调用，收集源文件 imports，再查找该文件内定义的 callee；不是只有 README 声称支持。[build_context_from_jsonl.py](https://github.com/HotFrom/VulAgent/blob/main/Context%20construction%20tool/build_context_from_jsonl.py)
- 所需输入含 `func_name`、`file_name`、`commit_url`、`func`。源码显示仅下载指定 commit 的一个源文件；Python callee 的查找模式是行首 `def`，跨文件导入和类方法的定义覆盖不充分。这些是静态读源码所得限制，未做运行验证。[同一 builder](https://github.com/HotFrom/VulAgent/blob/main/Context%20construction%20tool/build_context_from_jsonl.py)
- builder 按相邻两行一对处理，把第一行构建的同一份 context 复制到第二行。接入漏洞/修复对时，必须核对 vulnerable/fixed 两个版本是否共用错版本的上下文；建议按各自真实 checkout 单独建 context。[同一 builder](https://github.com/HotFrom/VulAgent/blob/main/Context%20construction%20tool/build_context_from_jsonl.py)
- 官方主 runner 的 `analyse` 接收函数、项目与 context，不接收 ground-truth CWE；`target` 用于结果度量。依赖/模型端点、JSONL 字段和 prompt 文件路径仍需适配。[VulAgent-Qwen.py](https://github.com/HotFrom/VulAgent/blob/main/Quickly%20reproduce%20the%20experiment/VulAgent-Qwen.py)

建议优先复现作者原来的“静态 context + 多 Agent 验证”设置。若另外把 context builder 改为 VulnHunter 的自适应仓库检索，必须注明是改编 baseline，以免改变作者方法后仍沿用原方法名称。

## VulnLLM-R 与 VulTrial：模型/推理机制的对照

- VulnLLM-R 官方发布 7B 权重，README 给出 vLLM 与 `--language python c java` 的测试命令；模型推理本身有清晰复现入口。安装说明涉及 Git LFS、训练子包与本地 GPU 推理，不能据此给出未经验证的最低显存需求。[官方代码与命令](https://github.com/ucsb-mlsec/VulnLLM-R)、[模型](https://huggingface.co/UCSB-SURFI/VulnLLM-R-7B)
- `repo_level` 是该项目的数据/测试模式名称，不能仅凭名称断言它完整实施了“把未知整仓交给 Agent、自主定位所有漏洞”。本轮只核实 README 的模型测试入口，**未验证完整 Agent scaffold**。[官方 README](https://github.com/ucsb-mlsec/VulnLLM-R)
- VulTrial 可作为多 Agent 辩论对照，但其原主任务仍是函数级漏洞判断。作者原版复现链接为 Figshare；本轮不能核实该包的完整性与执行条件，不使用第三方或当前 404 的同名 GitHub 仓库作为作者官方代码。[原论文 v2](https://arxiv.org/html/2505.10961v2)、[作者复现包](https://figshare.com/s/1514bc9a7aa64b46d94e)

## RepoAudit、IRIS、LLMxCPG：语言与漏洞范围的复现门槛

- **RepoAudit** 当前官方 README 的默认演示为 `benchmark/Python/toy`，因此不能简单写“没有 Python 支持”。但官方原生扫描类别仍是 MLK、NPD、UAF；论文核心实测是这类数据流/内存 bug。当前 RepoPairBench 若以注入/鉴权类为主，需要新的 source/sink、规则与分析 prompt，属方法移植。[官方 README](https://github.com/PurCL/RepoAudit)、[启动脚本](https://github.com/PurCL/RepoAudit/blob/main/src/run_repoaudit.sh)
- **RepoAudit** 的官方安装涉及 Python 3.13、Tree-sitter 绑定和模型 API；原论文方案无需构建目标项目，适合作为编译无关整仓审计对照。[官方安装](https://github.com/PurCL/RepoAudit)、[ICML 正式版](https://proceedings.mlr.press/v267/guo25n.html)
- **IRIS** 输入为 Java 项目与 CWE，需构建项目并生成 CodeQL database。论文原版四类是 CWE-22/78/79/94；仓库后续扩展了 CWE 与数据规模，复现时应固定版本，避免把新版样本数说成原论文实验数。[ICLR 正式论文](https://proceedings.iclr.cc/paper_files/paper/2025/file/582d4e27fa24168f3af1f4582655034b-Paper-Conference.pdf)、[官方仓库](https://github.com/iris-sast/iris)
- **LLMxCPG** 官方依赖 Docker、Joern（测试版本 4.0.408），查询模型从 Qwen2.5-Coder-32B-Instruct 微调，检测模型从 QwQ-32B-Preview 微调；有公开权重集合与源码，硬件和推理成本应单独预算。[官方仓库](https://github.com/qcri/llmxcpg)
- **LLMxCPG** 原论文虽介绍 SVEN 全集含 C/C++ 与 Python，但实际选用的测试 CWE 是越界、整数溢出、UAF 等内存类别。不能将“使用 SVEN”推导成“Python 注入漏洞已验证”；本轮没有核实官方 Python 前端和 RepoPairBench 的端到端适配。[原文 §4.1 与 Table 1](https://www.usenix.org/system/files/usenixsecurity25-lekssays.pdf)

## 已检索但不作为强推荐

- **VulnAgent-R2: Evidence-Calibrated Multi-Agent Auditing for Repository-Level Vulnerability Detection**，2026 年 3 月 arXiv。作者链接的 [renweimeng/Vlun-Agent-X](https://github.com/renweimeng/Vlun-Agent-X) 确实有 `src`、`tests`、CLI 和 API，并非只有 README；但仓库仍以 VulnAgent-X 命名，README 将 verification 标为占位实现。本轮未确认 R2 所称的 CER、build-aware plan 与 cost-risk Pareto 三模块完整对应，暂不作为强复现推荐。[论文](https://arxiv.org/abs/2603.13384)、[官方 README](https://github.com/renweimeng/Vlun-Agent-X)、[scheduler 源码](https://github.com/renweimeng/Vlun-Agent-X/blob/main/src/vulnagentx/core/scheduler.py)
- **Antaeus: Hunting Repository-Level Logic Vulnerabilities via Context-Grounded LLM Reasoning**，2026 年 7 月 arXiv。真正是整仓 C/C++ 逻辑漏洞检测，聚焦 CWE-200/284；本轮未在论文与检索中确认作者可用实现，暂作相关工作而非首轮复现。[原论文](https://arxiv.org/html/2607.01138v1)
- **LLMDFA: Analyzing Dataflow in Code with Large Language Models**，NeurIPS 2024。官方实现以 Java Juliet 与 Android 数据流 bug 为主；框架自称语言无关，但迁移 Python 要修改解析器与提取逻辑，不适合作为当前 Python 实验的低成本直接 baseline。[出版方](https://proceedings.neurips.cc/paper_files/paper/2024/hash/ed9dcde1eb9c597f68c1d375bbecf3fc-Abstract-Conference.html)、[官方代码](https://github.com/chengpeng-wang/LLMDFA)
- **PrimeVul** 是函数级 C/C++ 数据集与评估协议，可借鉴 paired metrics，不能单独当作一个 Agent 漏洞检测方法。[官方数据与代码](https://github.com/DLVulDet/PrimeVul)
- **VulnBot** 的相关论文/官方实现做自动渗透测试；其目标、输入和评估不等同于给定 Python 函数及仓库上下文的源代码漏洞分类。[作者仓库](https://github.com/KHenryAegis/VulnBot)

## 公平比较的建议

1. 固定 RepoPairBench 的相同样本、目标函数与漏洞/修复 checkout；逐版本构造 context，不向任何方法暴露 CVE 描述、补丁差异或真实标签。
2. DREA、VulAgent、VulTrial 尽量使用同一 backbone、推理预算和温度；VulnLLM-R 单列为专用模型对照，不能把模型差异混算成 Agent 架构贡献。
3. “指定 CWE”与“未知 CWE”分开报告；IRIS 原生要 CWE，因此不能悄悄给它 oracle 信息而让其他方法无此信息。
4. 同时报告 pair correctness、误报与单样本成本；如果迁移后的方法增加了整仓检索、动态验证或 source/sink 定制，在方法名称和设置中明确说明。

以上为实验设计建议，不是已经完成的实验或原论文结论。
