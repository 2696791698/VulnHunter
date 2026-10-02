# VulnHunter 中文预印本框架稿

- Article.tex：论文主稿；VulnHunter 的待测实验数值用 nan 命令占位。
- references.bib：本稿引用的论文。
- zHenriquesLab-StyleBioRxiv.cls 与 zHenriquesLab-StyleBib.bst：从用户指定的预印本模板复制。为支持中文 XeLaTeX，类文件去掉了仅供 pdfLaTeX 使用的编码设置，调整 cleveref 加载顺序，并将 bioRxiv 页脚改为中性的 Preprint draft。当前稿恢复模板的双栏双面布局；DREA 对比表按单栏宽度排版，保持表号顺序。
- VulnHunter-中文预印本框架-图1新版.pdf：当前编译预览。原同名 PDF 被阅读器占用，保留为此前版本。
- Figures/VulnHunter-figure1-studio-pro.pdf：当前图 1 的矢量插图，采用 Figure Studio Pro 的源证据审查与论文线稿风格。`Figures/figure-studio-pro/` 保存设计记录、候选图与最终生成脚本；同名 `.drawio` 是可编辑的结构版，`.png` 可快速预览。此前的 `VulnHunter-figure1.*` 保留供对照。

在本目录运行 latexmk -xelatex -bibtex -interaction=nonstopmode -halt-on-error -outdir=build Article.tex 可重新编译。

本文以 DREA 为唯一外部性能基线，已录入其论文中的公开指标；VulnHunter 结果均为 nan。本文目前是写作框架，不是投稿定稿。需补入作者、单位、正式实验配置、结果、消融和可复核案例；数据集固定规模与性能结果应区别对待。现有旧稿 ../vulnhunter_zh.tex 没有被覆盖。



