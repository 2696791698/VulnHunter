# VulnHunter 架构图：用户原图参考版

参考源文件：`C:/Users/h2696/Desktop/Architecture Diagram.drawio`。

本版围绕原图的算法结构重排版式：Prompt、Codebase、Project Directory Tree 输入 LLM；Joern、Semgrep、CodeQL 汇入 Static Analysis Tools，通过 MCP 接入 Static Analysis；Analysis & Exploitation Loop 包含 Static Analysis、Attack Planning、Dynamic Verification 以及 State Management / Blackboard；Codebase 通过 Volume 挂载到 Docker Container，Interactive Shell 与 Container Creation 支撑 Subagent / Executor；闭环输出 PoC Generation & Vulnerability Report。

保留原图全部 15 条有向关系，并将隐含的阶段顺序与黑板反馈补成 4 条显式连线：静态分析到攻击规划、攻击规划到动态验证、动态验证到黑板、黑板反馈到静态分析。原图的反向起点箭头按实际箭头方向解释为 Subagent 到 Dynamic Verification。关系核对结果见 `relationship-check.json`。

Joern 的副标题补充当前项目通过 CodeBadger 接入 CPG 的实现信息。图中使用中文主标签，并保留原图的主要英文模块名称。此图是算法架构视图，状态管理与黑板位于审计闭环内。

- `vulnhunter-architecture.drawio`：16:9 单页可编辑源文件。
- `vulnhunter-architecture.pptx`：单页 PowerPoint，模块、文字与连线为原生可编辑对象。
- `vulnhunter-architecture.png`：1920 × 1080 图片，由实际 PPT 渲染。
- `vulnhunter-architecture.pdf`：PowerPoint 导出的矢量 PDF。
- `vulnhunter-architecture.svg`：原生 SVG，包含文本，无 foreignObject。
- `generate_architecture.py`：生成器，复用相邻 `architecture-ppt/generate_architecture.py` 的基础绘图函数。

Draw.io 页数和 PPT 幻灯片数均为 1。输出经 [drawio2pptx 0.0.7](https://pypi.org/project/drawio2pptx/0.0.7/) 转换，并核对源文件与 PPT 的文字完全一致，检查中文渲染和连线。
