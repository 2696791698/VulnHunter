# VulnHunter 论文架构图：参考图重绘版

参考用户提供的 `Architecture Diagram.drawio`、`Architecture Diagram.svg` 和 DREA 架构截图。内容来自此前已核对的项目实现；借用圆角分组、低饱和配色、衬线字体、白色功能条和填充箭头的视觉风格。

本版聚焦方法机制：任务输入 → 主审计 Agent 与静态分析工具 → Docker 执行子代理 → 追加式证据黑板 → 结构化判定及复现报告。黑板证据回流主代理，并参与最终结果整理。

## 文件

- `vulnhunter-architecture.drawio`：Draw.io MCP 创建及编辑的源文件，只包含本版中英文两个页面。
- `vulnhunter-architecture-en.pdf`、`vulnhunter-architecture-zh.pdf`：嵌入字体的矢量 PDF，建议用于论文。
- 同名 `.svg`：可编辑文字的矢量图；同名 `.png`：2190 × 1182 像素预览。

英文版采用 Times New Roman，中文版采用微软雅黑。已检查源文件 ID、连接端点、文字标签、矢量输出及最终渲染。

## 建议图题

**VulnHunter architecture.** The audit agent refines vulnerability hypotheses using repository context and static-analysis findings, and delegates dynamic verification to a container executor. An append-only blackboard feeds execution evidence back to the audit agent and supports the structured verdict and reproduction report.

**VulnHunter 系统架构。** 主审计 Agent 结合仓库上下文与静态分析线索更新漏洞假设，并委派容器执行子代理开展动态验证。追加式证据黑板将执行证据回流主代理，支撑结构化判定及漏洞复现报告。

双栏论文建议以 `figure*` 跨栏插入 PDF。若 LaTeX 主文件位于 `paper/`，图片路径为 `figures/architecture/paper-style/vulnhunter-architecture-en.pdf`。

```latex
\begin{figure*}[t]
  \centering
  \includegraphics[width=\textwidth]{figures/architecture/paper-style/vulnhunter-architecture-en.pdf}
  \caption{VulnHunter architecture. Static-analysis findings guide dynamic verification, while an append-only blackboard feeds execution evidence back into auditing and structured finalization.}
  \label{fig:vulnhunter-architecture}
\end{figure*}
```
