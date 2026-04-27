# VulnHunter

**VulnHunter** 是一款智能漏洞检测工具，旨在帮助安全专业人员分析并发现代码库中的安全风险。

# 基础环境

- **Linux or WSL**（推荐使用Ubuntu-24.04）
- **Python** 3.10+（推荐使用 3.13）
- **Node.js** v25.6.0 或更高版本
- **uv**
- **Docker**
- **CodeQL CLI** - 必须安装并添加到 PATH 环境变量中（https://github.com/github/codeql-cli-binaries/releases）

# 快速开始

## 工具准备

> CodeQL 和 codebadger 需使用本仓库中提供的修改后的版本
>
> 本项目共需配置四种MCP工具，分别为：codebadger，CodeQL，Semgrep，docker-mcp，其中 docker-mcp 还需要运行配套的 docker-manager

### codebadger

#### 1. 安装 Python 环境

```bash
uv venv --python 3.13
uv pip install -r requirements.txt
```

#### 2. 启动 Docker 服务（Joern）

```bash
docker compose up -d
```

#### 3. 启动 MCP 服务

```bash
uv run main.py
```

#### 4. 关闭 MCP 服务

```bash
# Ctrl+C
```

### CodeQL MCP

#### 1. 通过 npm 安装

```bash
npm install -g ./codeql-development-mcp-server-schema-fixed-2.25.2-schema-fixed.8.tgz
```

### Semgrep

遵循官方文档安装即可（https://semgrep.dev/docs/mcp）

### docker-mcp

遵循官方仓库安装即可（https://github.com/DullJZ/docker-mcp，https://github.com/DullJZ/docker-manager）

## 数据集提取

### 脚本介绍

`extract_pyvul_dataset.py`

该脚本会从 PyVul 的 GitHub advisory commit 链接里提取样例。每个样例会导出成两个完整项目版本：

- `Alpha`：修复前版本，也就是修复 commit 的父版本。
- `Beta`：修复后版本，也就是修复 commit 本身。

输出目录格式：

```text
dataset/
  CWE-79_0001_plotly_dash_GHSA-547x-748v-vp6p/
    Alpha/
    Beta/
    meta.json
```

项目名格式为：

```text
CWE编号_样例序号_GitHubOwner_仓库名_漏洞编号
```

例如：

```text
CWE-79_0001_plotly_dash_GHSA-547x-748v-vp6p
```

### 运行前准备

需要本机能使用：

```powershell
python
git
```

可选安装 `tqdm`，用于显示更好看的进度条：

```powershell
pip install tqdm
```

如果没有安装 `tqdm`，脚本也能运行，只是会使用简单文本进度条。

### 查看可提取样例总数

```powershell
python extract_pyvul_dataset.py --count-only
```

输出：

```text
[info] total extractable candidate samples: 1599
```

这里的 `1599` 就是当前元数据里可以候选提取的样例总数。

提取全部样例

```powershell
python extract_pyvul_dataset.py
```

默认输出到：

```text
./dataset
```

> 注意：全部提取会 clone 很多 GitHub 仓库，耗时和占用空间都会比较大。
>

### 提取指定范围

比如只提取第 20 个到第 30 个样例：

```powershell
python extract_pyvul_dataset.py --start 20 --end 30
```

`--start` 和 `--end` 都是从 1 开始计数，并且 `--end` 包含在范围内。

所以：

```powershell
--start 20 --end 30
```

会提取第 `20, 21, ..., 30` 个样例，一共 11 个。

### 从某个位置开始提取固定数量

比如从第 101 个样例开始，提取 50 个：

```powershell
python extract_pyvul_dataset.py --start 101 --limit 50
```

> 注意：`--limit` 不能和 `--end` 同时使用。
>

### 指定输出目录

```powershell
python extract_pyvul_dataset.py --start 20 --end 30 --output-dir my_dataset
```

这样会输出到：

```text
./my_dataset
```

### 跳过已经提取完成的样例

如果之前已经提取过一部分，可以加：

```powershell
python extract_pyvul_dataset.py --start 20 --end 30 --skip-existing
```

如果某个项目目录里已经存在：

```text
Alpha/
Beta/
meta.json
```

脚本会直接跳过它。

### 写出样例索引文件

如果想先保存本次选中样例的索引：

```powershell
python extract_pyvul_dataset.py --start 20 --end 30 --write-index
```

会生成：

```text
dataset/cases_index.jsonl
```

里面每一行是一个样例的元信息，包括 CWE、仓库地址、修复 commit、修复前 commit 等。

### 按条件筛选

只提取某个 CWE：

```powershell
python extract_pyvul_dataset.py --cwe CWE-79
```

只提取有 CVE 编号的样例：

```powershell
python extract_pyvul_dataset.py --require-cve
```

只提取有 GHSA 编号的样例：

```powershell
python extract_pyvul_dataset.py --require-ghsa
```

只提取仓库名或 owner 里包含某个字符串的样例：

```powershell
python extract_pyvul_dataset.py --repo-contains django
```

这些筛选条件可以组合使用，例如：

```powershell
python extract_pyvul_dataset.py --cwe CWE-79 --require-ghsa --start 1 --limit 10
```

### 常用参数说明

| 参数                       | 作用                                         |
| -------------------------- | -------------------------------------------- |
| `--count-only`             | 只输出可提取样例数量，不真正提取项目         |
| `--start N`                | 从第 N 个样例开始，默认是 1                  |
| `--end N`                  | 提取到第 N 个样例，包含 N                    |
| `--limit N`                | 从 `--start` 开始最多提取 N 个               |
| `--output-dir DIR`         | 指定输出目录，默认是 `dataset`               |
| `--cache-dir DIR`          | 指定缓存目录，默认是 `.pyvul_cache`          |
| `--skip-existing`          | 已经有 `Alpha/Beta/meta.json` 的样例直接跳过 |
| `--write-index`            | 写出 `cases_index.jsonl` 索引文件            |
| `--force-refresh-metadata` | 重新下载 PyVul 元数据                        |
| `--max-failures N`         | 失败 N 个样例后提前停止                      |
| `--cwe CWE-79`             | 只提取指定 CWE                               |
| `--require-cve`            | 只保留带 CVE 的样例                          |
| `--require-ghsa`           | 只保留带 GHSA 的样例                         |
| `--repo-contains TEXT`     | 只保留 owner/repo 中包含指定文本的样例       |

## Agent 配置

### 1. 安装 Python 环境

```bash
uv sync
```

### 2. 拉取 Docker 镜像

```bash
docker pull mcr.microsoft.com/devcontainers/anaconda:3
```

### 3. 环境变量

```
# .env
# OpenAI 或兼容 OpenAI API 服务的 API Key
OPENAI_API_KEY=
# API 基础地址
OPENAI_BASE_URL=

# 是否开启 LangSmith 追踪, 表示记录 LangChain / LangGraph / Deep Agents 的运行链路
LANGSMITH_TRACING=true/false
# 用于把追踪数据上传到你的 LangSmith 账号
LANGSMITH_API_KEY=
# LangSmith 项目名, 追踪记录会归档到这个项目下
LANGSMITH_PROJECT=
```

### 4. 审计单个项目（检测环境是否配置完整）

```

```

### 5. 跑测评

```

```

# 踩过的坑

- 强烈建议在Linux环境下运行本项目，Windows环境则使用WSL（大模型喜欢使用Linux风格的路径，而Windows下跑的codebadger则会要求使用Windows风格的路径，导致路径不匹配报错）

- 如果你的系统是Windows且安装了Docker Desktop，请上网查询教程，禁止Docker Desktop接管WSL里的Docker，否则你以为在WSL启动容器实际上还是在Windows里跑的，会触发上一条报错

- 如果你的系统是Windows且使用了如Clash Verge这种代理软件并开启了TUN模式，请把WSL网络模式调整成Mirrored，并使用 `wsl --update --pre-release` 把WSL更新到最新的预发行版本来解决诸如以下的报错：

  ```
  wsl: 出现了内部错误。 
  错误代码: createinstance/createvm/configurenetworking/0x8007054f 
  wsl: 无法配置网络 (networkingmode mirrored),回退到 networkingmode none。 
  wsl: 检测到 localhost 代理配置,但未镜像到 wsl。
  nat 模式下的 wsl 不支持 localhost 代理。
  ```

# Q&A

Q：为什么agent中要禁用那么多工具

A：因为这些工具非常容易会引起报错导致整个agent停止，并且他们都是与代码审计无关的工具，禁用它们并不会影响最终的审计效果

# 致谢

本项目的完成离不开以下项目：

* [deepagents](https://github.com/langchain-ai/deepagents)
* [PyVul](https://github.com/billquan/PyVul)
* [codebadger](https://github.com/Lekssays/codebadger)
* [codeql-development-mcp-server](https://github.com/advanced-security/codeql-development-mcp-server)
* [semgrep](https://github.com/semgrep/semgrep)
* [docker-mcp](https://github.com/QuantGeekDev/docker-mcp)
* [docker-manager](https://github.com/DullJZ/docker-manager)

# 开源许可

![GPL-v3](https://www.gnu.org/graphics/gplv3-127x51.png)
