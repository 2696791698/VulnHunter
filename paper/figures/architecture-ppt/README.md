# VulnHunter 总体架构图

根据 2026-10-03 当前工作区实现绘制，采用 pptgen-drawio 的经典学术配色。16:9 单页，深蓝表示调用和数据流，金色表示事实及证据回流，灰色虚线表示模型接入和归档。

- `vulnhunter-architecture.drawio`：Draw.io 可编辑源文件。
- `vulnhunter-architecture.pptx`：单页 PowerPoint，文字、模块和连线为可编辑对象。
- `vulnhunter-architecture.png`：1920 × 1080 PNG，来自实际 PPT 渲染。
- `vulnhunter-architecture.pdf`：PowerPoint 导出的单页矢量 PDF。
- `vulnhunter-architecture.svg`：原生 SVG，含文本，无 foreignObject。
- `generate_architecture.py`：共用布局生成 Draw.io 与 SVG。

主审计 Agent 按需调用静态分析工具并规划验证；executor 通过 docker-mcp 在任务专属容器中准备环境、执行 PoC 和观察影响，调用 append_blackboard 追加事实和证据；主 Agent 每轮读取黑板事实，最终结论和黑板共同输入结构化结果整理。

架构依据：`audit_agent.py` 中的 `get_analysis_tools`、`create_audit_agent`、`append_blackboard`、`build_blackboard_middleware`、`invoke_audit_agent` 和 `run`；`audit_result.py` 中的 `AuditAssessment` 和 `finalize_audit_result`；`web/server/main.py` 的服务桥与任务队列；`web/server/evaluation.py` 的评测状态和日志；`agent_tracing.py` 与 `web/server/trace_archive.py` 的回调及归档；`create_model.py` 的共享模型配置。

黑板是单次审计中的 Agent 状态，图中的 JSONL / Trace 归档属于运行支撑。结构化结果整理是审计结束后的模型调用。图中显示当前二分类判定策略：实际攻击成功并观察到安全影响才能输出 1；这一策略属于系统实现，不是独立复现实验的证明。

源文件使用独立文本框，无 HTML 换行或图片形式的文字。导出使用 [drawio2pptx 0.0.7](https://pypi.org/project/drawio2pptx/0.0.7/)，并核对 Draw.io 页数和 PPT 幻灯片数均为 1。
