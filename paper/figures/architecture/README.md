# VulnHunter 论文架构图

根据 2026-10-03 工作区中的实际实现绘制。使用 Draw.io MCP 创建、编辑并导出；可编辑源文件包含中文、英文两个页面。

## 文件

- `vulnhunter-architecture.drawio`：完整可编辑源文件。
- `vulnhunter-architecture-zh.pdf` / `-en.pdf`：嵌入字体的矢量 PDF，推荐用于 LaTeX。
- `vulnhunter-architecture-zh.svg` / `-en.svg`：保留文字和矢量图形，固定为浅色配色。
- `vulnhunter-architecture-zh.png` / `-en.png`：1688 × 1233 像素预览。

在 Draw.io 中选择「文件 → 打开」载入 `.drawio`，底部页签可切换中英文。

## 架构依据

- `audit_agent.py:452`：CodeQL、Semgrep、CodeBadger 的 MCP 接入。
- `audit_agent.py:256`：黑板事件按 ID 合并；每轮由事件重建黑板文本。
- `audit_agent.py:591`：主审计 Agent、仅拥有容器工具及追加黑板工具的 executor。
- `audit_agent.py:700`、`audit_result.py:104`：主 Agent 最终结论和黑板事实共同输入结构化结果整理。
- `web/server/main.py`：FastAPI 服务桥、任务队列、仓库准备、运行观测与资源生命周期。
- `web/server/evaluation.py`：数据集评测、状态恢复、指标汇总和 JSONL 日志。
- `agent_tracing.py`、`web/server/trace_archive.py`：回调事件及逐 Trace 持久化归档。
- `web/package.json`：Vue 3 Web 控制台。

黑板是审计过程中的 Agent 状态；本地持久化模块保存任务、评测、Trace 和仓库快照。结构化结果整理负责输出格式及字段一致性校验。静态工具和动态验证均按需调用。

## 图题

中文：**VulnHunter 系统总体架构。主审计 Agent 结合静态分析线索更新漏洞假设，并按需委派执行 Agent 在任务专属容器中开展动态验证；执行证据通过追加式黑板回流，最终生成结构化审计结果。**

英文：**Overview of the VulnHunter architecture. The main audit agent refines vulnerability hypotheses using static-analysis evidence and delegates dynamic checks to an executor operating in a per-task container. Evidence returns through an append-only blackboard and supports structured finalization.**

## LaTeX 插图

以下路径适用于主文件位于 `paper/` 的情况；模板位于其他目录时调整相对路径。双栏论文建议使用跨栏 `figure*`。

```latex
% Preamble: \usepackage{graphicx}
\begin{figure*}[t]
  \centering
  \includegraphics[width=\textwidth]{figures/architecture/vulnhunter-architecture-en.pdf}
  \caption{Overview of the VulnHunter architecture. Static-analysis evidence guides dynamic checks; an append-only blackboard feeds observed evidence back into auditing and structured finalization.}
  \label{fig:vulnhunter-architecture}
\end{figure*}
```

中文稿将文件名替换为 `vulnhunter-architecture-zh.pdf` 并使用中文图题。正文可写 `如图~\ref{fig:vulnhunter-architecture} 所示`。

## 导出检查

- 每页 cell ID 唯一、连接端点有效，共 47 个可见文字标签。
- 两份 PDF 均为单页矢量图，已嵌入所用字体并检查中文及英文渲染。
- SVG 使用原生文本，无 `foreignObject`；中文按 Draw.io 源文件校正，消除了 MCP 导出的编码问题。
- PNG 由最终 PDF 渲染生成，已目视检查文字、连线与边界。
