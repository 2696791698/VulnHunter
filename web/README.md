# VulnHunter 环境自检面板

把 `check_environment.py` 的五项依赖检测（CodeBadger / CodeQL / Semgrep / docker-mcp / Model）
做成一个可视化面板。Vite + Vue 3 + TypeScript + Tailwind v4 + shadcn-vue。

## 快速开始

```bash
npm install
npm run dev
```

打开 http://localhost:5173 。**面板本身不含任何内容**：所有数据都来自下面那个桥接服务，
服务没起来时页面会显示「没有数据 / 无法连接」，而不是拿示例数据顶上。

## 检测真实环境

面板通过 `/api/*` 访问同目录下 `server/` 里的 Python 桥接服务；它调用 `check_environment.py`
里原本的检测函数，并把结果转成 JSON。桥接服务同时是每个检查项**展示信息**的唯一来源
（名称、说明、传输方式、依赖的环境变量、连接目标、图标），前端不留副本。

> **这个项目跑在 DinD devcontainer 里，桥接服务必须在容器内用 `/home/vscode/.venv/bin/python`
> 启动。** 宿主机的 Python 没有 `deepagents` 等项目依赖，用它会直接 `ModuleNotFoundError`；
> `.env` 里 `MODEL_NAME` / `OPENAI_API_KEY` 等也要在容器环境里才生效。

容器内在仓库根目录同步依赖；默认的 `bridge` 依赖组包含 FastAPI 和 Uvicorn，
后续运行 `uv sync` 或 `uv run` 也会保留它们：

```bash
uv sync
```

然后在**仓库根目录**启动桥接服务（`/workspaces/VulnHunter`），这样 `check_environment.py`
能读到同目录的 `.env`：

```bash
/home/vscode/.venv/bin/python web/server/main.py
```

刷新页面后数据源标签会变成「实时数据」，点「重新检测」就会真的执行检测。桥接服务把各项
并发执行（原始脚本是串行），所以整轮耗时取决于最慢的那一项；卡片上的耗时是各自的真实耗时，
检测概览里的「本次耗时」是各项耗时之和。页面只呈现当前这一次检测，不做跨次的历史统计。
检测结果也不落盘：桥接服务重启后回到「未检测」，而不是回放一份没人要看的历史。

### 容器里跑前端

`web/node_modules` **不能**放在 Windows 的 bind mount 上：那个文件系统不支持符号链接，
npm 生成不了 `node_modules/.bin`，esbuild 的平台二进制也连不上，容器里会直接 `vite: not found`。

`devcontainer.json` 里已经加了一个命名卷盖住这个目录：

```json
"mounts": [
  "source=vulnhunter-web-node_modules,target=${containerWorkspaceFolder}/web/node_modules,type=volume"
]
```

**重建容器后**在容器里装一次就行，宿主机的 `web/node_modules` 不受影响（卷把它遮住了，
宿主机继续用自己那份 Windows 包）：

```bash
cd web
sudo chown -R vscode:vscode node_modules   # 命名卷首次挂载时属主是 root
npm install && npm run dev -- --host 0.0.0.0
```

`forwardPorts` 里已经声明了 `5173`（面板）和 `8901`（桥接），VS Code 会把它们转发到宿主机，
直接用本机浏览器打开 `http://localhost:5173` 即可，页面会自动连上容器里的桥接。

## Token 用量

概览页的 token 统计来自 agent 的模型调用 span —— 桥接把每个 span 的 `usage` 累加起来。
`agent_tracing.py` 会在上报前把两种口径归一化：

| 字段 | OpenAI 口径 | LangChain 归一化口径 |
| --- | --- | --- |
| `inputTokens` | `prompt_tokens` | `input_tokens` |
| `outputTokens` | `completion_tokens` | `output_tokens` |
| `totalTokens` | `total_tokens` | `total_tokens` |
| `cacheReadTokens` | `prompt_tokens_details.cached_tokens` | `input_token_details.cache_read` |
| `cacheCreationTokens` | `prompt_tokens_details.cache_creation_tokens` | `input_token_details.cache_creation` |

两个派生量由桥接算：

- `newInputTokens = inputTokens − cacheReadTokens − cacheCreationTokens`（下界 0）。两种口径里
  `inputTokens` **都含**缓存部分（LangChain 的 `input_tokens` 明确如此，OpenAI 的 `prompt_tokens`
  也包含 `cached_tokens`），所以减掉缓存才是真正新发的 prompt。
- `cacheHitRate = cacheReadTokens / inputTokens × 100`。

> **「没上报」在链路上仍然是 `None`。** 如果某次调用的 usage 里既没有 `input_token_details`
> 也没有 `prompt_tokens_details`，缓存字段会一路以 `None` 传下去 —— 很多 OpenAI 兼容网关根本
> 不发这些字段。界面分两种处理：两个缓存 token 数（缓存创建 / 缓存命中）按 **0** 显示，它们
> 本来就是计数，缺了当 0 读不算错；但**缓存命中率保持「没有数据」**，因为那里冒出一个 0% 会
> 被读成「命中率就是 0」的结论，而我们其实并不知道。

概览页的 token 卡还分一层：`totals` 为 `null`（连上了桥接但还没跑过任何东西）时整张卡显示
**0**，命中率也跟着显示 0% —— 那是「一个都没有」，不是「不知道」。一旦有请求跑过、只是缓存
字段没上报，命中率才回到「没有数据」。这也是**这张卡独有**的处理：耗时、延迟、环境检测这类
读数是「测了才有」，缺了显示 0 就是编造，所以仍是「没有数据」。

概览页上半张卡是总计与四项分解，下半张卡是四条各自独立的渐变面积（缓存创建 / 缓存命中 /
输入 / 输出），右上角可切时间范围与分桶粒度。几个实现细节：

- **不堆叠，每条线画在自己的数值上。** 四段是同一个总量的分解（它们相加等于总量），但堆叠
  面积图会把每段的边线落在它**下面所有段的累计和**上，于是一个数值小的段被画在数值大的段
  *之上*，读起来像它是更大的那个：`输入` 在 tooltip 里小于 `缓存命中`，图上却在它上面。
  分开画之后每条线都等于它自己那一行的数字。代价是图里不再有哪个高度等于总量。
- **一个 `VisArea` 一段，靠单 accessor 避开堆叠。** Unovis 的 `Area` 打开堆叠的条件正是
  `y` 是数组（`this.stacked = Array.isArray(this.config.y)`），config 里既没有 `stacked`
  属性也没有别的开关。所以这里是 `v-for` 出四个各带一个 accessor 的 `VisArea`，每个都填
  自己的 0→数值。另一种错法是自己算好累计再交给 `y`：那会把每段上方的累计多加一遍，真实
  峰值 78.7 万会被画成 157 万。
- **渐变走容器的 `svgDefs`**。`Area` 没有渐变支持 —— `color` 被原样写进 path 的 `fill`，
  所以 `url(#…)` 会透传；而容器会把 `svgDefs` 里的任意 SVG 片段解析进它自己的 `<defs>`，
  渐变因此能和引用它的 path 待在同一个 `<svg>` 里。stop 的颜色写 `var(--color-<key>)`，
  那是 shadcn 的 `ChartStyle` 从本组件的 `chartConfig` 推出来、声明在图表容器上的，颜色的
  唯一来源仍然是 config。`stop-color` **用属性**写 `var()` 是有效的（实测解析成了实际颜色），
  不必绕成 inline style。
- **渐变框是每块面积自己的 bounding box**，所以每段在**自己**的高度上淡出：高的 `缓存命中`
  段跨越整张图的高度，矮的 `输出` 段则贴着它自己的顶色。代价是几段在低处互相重叠，颜色会叠
  在一起（三段都盖住 0→`输出` 那一段），越矮的段越难分辨。
- **`fill` 写成 `url(#…) <color>`**，末尾那个颜色是 SVG 的 paint fallback：引用没解析出来时
  退回平色，而不是整片填充消失（无效的 paint server 按规范会被当成 `none`）。
- **分桶键统一到 UTC**，标签由前端按浏览器时区渲染 —— 否则容器是 UTC、浏览器是 +08:00 时，
  同一张图上两个时间会打架。范围筛选两端都有界（"最近 24 小时"不该包含未来的桶）。
- **桶的粒度可选**（`?interval=1m|15m|1h|1d`，默认 `1h`），可选项由接口下发，选择器直接渲染。
- **只有一个桶时，每个系列各画一个标记点**。面积至少需要两个点才画得出东西，所以只有一个
  区间时整张图会是空的，那几个点就是唯一的可见内容。两个桶以上就不画了：顶边本身已经在说
  同一件事，多出来的点是没有图例的第五种颜色。

## 漏洞审查

填一个仓库地址和 commit，服务会把它拉取到专用检出目录，再交给 `audit_agent.py` 跑一次完整审查，
结论回填到任务列表里。`POST /api/audit/tasks` 建任务，`GET /api/audit/tasks` 看列表。

审查分两种**检测模式**，在表单顶部切换，两者共用同一条队列和同一套检出流程：

| 模式 | 表单字段 | 交给 agent 的东西 |
| --- | --- | --- |
| 项目检测 | 仓库地址 + commit | 整个检出目录 |
| 函数检测 | 再加函数所在文件、函数代码 | 整个检出目录 + 这一个函数的路径与源码 |

函数检测不多克隆、也不另起容器：提示词末尾多一段目标函数（`audit_agent.py` 的
`render_function_target()`），系统提示词里多一条范围约束（`FUNCTION_SCOPE_RULES`，只对这一个
函数下结论）。代码**原样**进提示词，只去掉首尾的空行——函数自己的缩进属于提交内容的一部分。
除代码外还给路径，是因为 agent 要读那个文件才拿得到参数来源和调用链，只给片段它只能对着片段猜。

两个填空的校验都在桥接服务里：

- **文件路径**必须是相对检出根目录的路径：不接受绝对路径、盘符和 `..` 路径段，字符集也收紧到
  一套安全字符。它唯一被使用的地方是拼接检出目录，这些限制让这个拼接在构造上就出不去。
- **函数代码**按字符数设上限（`MAX_FUNCTION_CODE_CHARS`，20000）。任务每变一次状态就把它整份
  追加进 `audit_tasks.jsonl`，上限是为了让这份历史有个界。
- 检出之后**验证路径存在**：找不到就把任务判失败并指名是哪个路径。路径是调用方给的，只有格式
  保证、没有存在保证；路径错了 agent 读不到文件，只凭片段答题，不如直接报出来。

`mode` 是函数检测上线后才有的字段；更早的任务在 `_public_task()` 里一律读作 `project`，旧记录
不需要迁移。

几个运行设计：

- **任务可并发运行。** 审计与测评共用有界 worker 池，默认同时运行 2 个任务。在「配置」页可以把
  最大并行数量实时调整为 1 到 16；调高时立即补充 worker，调低时不打断正在运行的任务，后续派发按新上限执行。
  也可通过 `AUDIT_MAX_CONCURRENCY` 环境变量设置。提高数量会同时增加 Docker、模型 API 和克隆仓库的资源占用。
- **每个任务有独立运行上下文。** 项目根路径、Docker 容器名和输出文件按任务隔离，不会因其他 worker
  改写模块级 `PROJECT_ROOT` 或抢用固定容器名。
- **Joern 服务按任务占用和释放。** 在 VulnHunter 中，`AUDIT_MAX_CONCURRENCY` 同时控制审计 worker
  和 CodeBadger 的 `MAX_ACTIVE_JOERN_SERVERS`；配置页调整会立即同步到两个运行中的服务。调低时
  已在使用的 JVM 等任务结束后退出；CPG 文件留在磁盘以便下次重新加载。
- **必须在工作线程里跑。** `run()` 内部调用 `asyncio.run()`，不能在请求的事件循环里嵌套调用。
- **检出目录放在容器原生路径**（默认 `/home/vscode/audits/<task-id>`，`AUDIT_ROOT` 可改）。
  项目目录是 Windows bind mount，`git` 往那里写 pack 文件会 `fsync` 失败。检出本身可以用
  url + commit 重新克隆，放在临时存储里没有代价；任务结束（成功、失败或取消）时会清理容器内挂载目录及宿主检出目录，任务记录和结论仍保留。
- **地址和 ref 都做白名单校验**（`URL_PATTERN` / `REF_PATTERN`），并且用 argv 数组调 git
  （从不过 shell）。以 `-` 开头的 ref 会被拒绝，避免被当成 git 参数。

任务状态变化会立刻追加到 `audit_tasks.jsonl`（同样已 gitignore、同样在超限时轮转），
所以重启服务后列表还在；上次进程被杀时停在「进行中」的任务，回放时会标成失败并说明原因。

## 数据集测评

「数据集测评」页在数据集上批量跑函数级审查：选定一个范围，把每个样例交给 agent 审查一次，
再拿 agent 的判定和数据集里的标注比对，边跑边出指标。

### 数据集从哪来

数据集文件在仓库根目录的 `benchmark/`，随代码一起走（只有元数据，不含上游仓库）：

```text
benchmark/drea/repopairbench_100.jsonl            # 100 组漏洞修复对
benchmark/drea/repopairbench_100_manifest.json    # 同一批的补充信息（修复 commit message 等）
```

`drea` 这一份是 DREA 论文（*DREA: Decoupled Reasoning and Exploration Agents for
Repository-Level Vulnerability Detection*，Internetware '26）公开产出的 **RepoPairBench 100**：
100 组 2021–2025 年的 Python 漏洞修复对，覆盖 48 个 CWE，每组给出修复 commit、漏洞版本函数
和修复版本函数。上游仓库不 vendor，运行时从 `repo_url` 现拉 —— 和函数检测走的是同一条检出流程。

数据集在 `evaluation.py` 的 `DATASET_SPECS` 里注册；再加一份就是把它的 JSONL（和可选的
manifest）放进 `benchmark/<id>/` 再登记一行。`EVAL_DATASET_ROOT` 可以改根目录（验证脚本就靠它
把数据集指向临时目录）。

### 一样本是「项 × 版本」

数据集里的「一项」是一组漏洞修复对；真正跑的是一个**样例**，也就是项的一个版本：

| 版本 | 检出 | 送进 agent 的函数 | 标注 |
| --- | --- | --- | --- |
| `vul` 漏洞版本 | 修复 commit 的**父提交**（`<commit>^`） | `code_before` | 有漏洞 |
| `sec` 修复版本 | 修复 commit 本身 | `code_after` | 无漏洞 |

检出逻辑与内容在 `evaluation.sample_input()`，检出和审查本身复用 `main.py` 里那套 `_clone` +
`audit_agent.run()`。给 agent 的东西和函数检测完全一样：整个检出目录 + 这一个函数的路径与源码。

> 父提交是用 git 的 `<commit>^` 表示的，而桥接对 ref 的校验（`REF_PATTERN`）默认不接受 `^`。
> 这里没有放宽那个白名单，而是在 `evaluation.REF_PATTERN` 里单独校验：ref 来自数据集文件而不是
> 调用方，字符集收紧到 `[0-9A-Za-z._/-]` 加一个可选的结尾 `^`。它一样是 argv 数组进去的，不过 shell。

### 范围怎么解析

范围（scope）有两部分，`evaluation.resolve_items()` 按这个优先级解析：

- **勾选的行**（`itemIds`）优先。这是页面在读者手动勾过之后发的东西；此时再套用筛选条件会把
  读者挑中的行悄悄丢掉。
- **筛选条件**（`projects` / `cweIds` / `search`）用于「筛出一批」的情形。`search` 是大小写不敏感
  的子串匹配，打在 id、项目名、文件路径、仓库地址、CVE 和 CWE 上。

**范围没有上限，也不截断**：测多少个由读者决定，后端不会替他把范围砍掉一截（截出来的前缀只代表
数据集里的一段，指标看着像数据集级的结论，其实不是）。页面也不劝：样例数就摆在「开始测评」旁边，
一个样例 = 一次完整审查，要不要付这个代价是读者自己的判断。

**筛选在后端做，不在页面做。** `GET /api/eval/datasets/{id}/items` 收 `project` / `cwe` / `search`
并返回匹配的行，用的是解析范围时的同一个谓词，所以「全选这些行」不可能选到跑不出来的东西。
facets（项目 / CWE 的选项和计数）则是在**整个数据集**上算的 —— 选项会随着使用而消失的选择器没法学。

页面每次编辑范围都会 `POST /api/eval/scope` 让后端解析一遍，把「N 个样例」显示出来；创建用的是
同一段代码，所以预览的数字就是会创建的数字。范围解析为空**不是错误**：预览要能显示「0 个样例」，
真正的失败只发生在拿着空范围去创建测评的时候。

### 判定从哪来

`audit_agent.py` 和 `base_agent.py` 都在审计结束后调用 Pydantic 结构化输出，返回如下 JSON：

```json
{
  "verdict": 0,
  "reproduction_report": null
}
```

`verdict` 为整数 `0` 表示无漏洞，`1` 表示有漏洞。判定为 `1` 时必须带复现报告，包含受影响位置、前提、复现步骤、预期影响、已观察到的影响、验证状态和证据；判定为 `0` 时报告为 `null`。评测从这个字段取值，不再从自由文本或 XML 标签中猜测。无效结构化结果会记为未命中；Agent 或模型调用失败则单独记为失败。

评测内部的文本标签使用 `vulnerable` 和 `non-vulnerable`。旧 journal 中的 `benign` 只作为读取兼容项，加载时会归一化为 `non-vulnerable`，新结果不会再写入旧标签。

### 指标

`evaluation.compute_metrics()`，口径跟 DREA 的 `code/process/eval/match.py` 对齐，数字可以和论文里
的比：

| 指标 | 定义 |
| --- | --- |
| 召回率 / 误报率 / 精确率 / F1 / 准确率 | 在单个实例上算 |
| Pair-Correctness | 一个 (漏洞, 修复) 对的两个成员**都**判对才算对 |
| 配对双判有漏洞 / 双判无漏洞 / 判反 | DREA 报的三个辅助分解 |
| Youden's J | 召回率 − 误报率 |

样例有三种结局，记账方式**故意不同**：

| 结局 | 计入指标吗 | 为什么 |
| --- | --- | --- |
| 给出了判定 | 是，进混淆矩阵 | 这就是要测的东西 |
| 跑了，但回答里没有判定标记 | 是，按**未命中**计 | agent 没按约定输出，是它自己的失败 |
| **没跑成**（拉取失败、服务重启、被取消） | **否**，单独计成 `failed` / `cancelled` | 它**没有测到模型** |

第三种必须排除，否则一个刚开就被取消的测评会显示「召回率 0% / 误报率 100%」—— 那是在替一次根本
没测过的运行给模型下结论。代价是排除失败会**高估**表面覆盖率，所以 `counted`（进矩阵的个数）和
`excluded` 都随接口下发，页面上写明「指标覆盖 N / M 个样例」，并把没跑成的样例单列一行。

其余口径：

- 只在**已经跑完**的样例上算：一个还在飞的测评报的是它已完成那部分的数字，而不是一个会在读者眼皮
  底下动的数字。
- **配对只在两个成员都给出了判定时才计入**（否则 `total` 和三个分解的分母会对不上）；被判反、判错
  的配对照常计入，它们正是要看的。
- `value` 在分母为 0 时是 `null` 而不是 0 —— 「一个都没有」和「不知道」在这里是两件事，和 token 卡上
  缓存命中率的处理一致。

### 怎么跑

样例和手动审查**共用同一条队列和有界 worker 池**，可以并发执行。默认并发数为 2，可在「配置」页
实时调整为 1 到 16，也可通过 `AUDIT_MAX_CONCURRENCY` 设置；调高时立即增加 worker，调低时等正在执行的样例结束后按新上限继续派发。
每个任务使用独立的检出目录、容器名和结果文件。测评样例和手动审计任务在容器清理后都会删除对应克隆目录，判定仍保存在任务记录中；
`.results/` 下的回答和诊断文件保留供排查。每个样例都要拉一次仓库再跑一次完整审查，所以一批全量仍可能需要几小时。

任务记录实时追加到 `eval_runs.jsonl`（已 gitignore、超 `EVAL_JOURNAL_MAX_MB` 时轮转），启动时回放。
回放时，上一轮仍在排队或运行的测评会变成 `paused`，不会自动执行。排队样例保持待运行；
正在拉取或审查的样例标成失败并写明服务重启。已经判定过的样例保留结论。

### 断点续测

全量 200 个样例可能需要几小时。手动点击「暂停测评」后，不再启动新样例；已经开始的样例会完成。
服务或电脑重启后，未完成的测评默认保持暂停。点击「继续测评」才把待运行样例重新排队，
并重跑因重启而中断的样例；已有结论不变。

- **已经判定过的样例不会因继续测评重跑**：进度从记录里重建，不从零开始。
- 继续测评不会自动恢复已取消或普通失败的样例。失败或未解析样例可用「重试无结论的」；
  已取消样例可用「重跑已取消」，沿用原测评和样例 ID，重跑结果直接计入原批次统计。
- 重启时正在跑的样例由用户点击继续后重跑；断电时拉了一半的检出目录会在下次拉取时删掉重建，
  `_clone()` 每次都从干净目录开始。

**断电最多丢一条记录**：记录一行一条，写完 `flush` 再 `fsync`（项目目录所在的文件系统接受
fsync —— 用 `os.fsync` 探过；万一哪天挂到不接受的存储上，就退化成只 flush）。回放本来就跳过
最后那半截 JSON，但半截行没有换行符的话，**下一条记录会黏在它后面一起丢**，所以启动时先给这种
尾巴补一个换行（`_heal_journal_tail()`）再开始写。丢掉的只会是「某样例刚从 `queued` 变成
`cloning`」这类中间状态，样例本身没有判定，续测时会重跑。

期刊里**不存函数代码**：函数体留在数据集里按 item id 查，否则 200 个样例每条状态变更都把
`code_before` / `code_after` 重写一遍。

### 接口

| 方法 | 路径 | 作用 |
| --- | --- | --- |
| GET | `/api/eval/datasets` | 可测评的数据集，含类型选项（`typeOptions`） |
| GET | `/api/eval/datasets/{id}/items` | 数据集里的项（可筛选）+ facets |
| POST | `/api/eval/scope` | 解析一个范围，不创建任何东西 |
| POST | `/api/eval/runs` | 解析范围并排队 |
| GET | `/api/eval/runs` | 全部测评，带进度与指标 |
| GET | `/api/eval/runs/{id}` | 一次测评 + 全部样例 |
| POST | `/api/eval/runs/{id}/pause` | 暂停新样例启动，已经开始的样例继续完成 |
| POST | `/api/eval/runs/{id}/resume` | 手动继续暂停的测评，排入待运行和因重启中断的样例 |
| POST | `/api/eval/runs/{id}/cancel` | 丢掉还没开始的样例，在跑的那个不动 |
| POST | `/api/eval/runs/{id}/retry` | 把没有判定的样例重新排队 |
| POST | `/api/eval/runs/{id}/retry-cancelled` | 显式重跑已取消样例，结果计入原批次统计 |
| DELETE | `/api/eval/runs/{id}` | 移除这次测评及其期刊记录 |

离线回归测试（不联网、不起容器、不调模型）：

```bash
/home/vscode/.venv/bin/python scripts/verify_evaluation.py
```

它在临时目录里造一个两提交的 git 仓库和一份一项目的数据集，用一个桩替掉 audit agent，检查父提交
检出的是修复前的代码、判定标记的解析、指标口径、取消/重试/回放。

## Agent 监控

「Agent 监控」区块按 LangSmith 的方式展示一次 agent 运行的 span 树：每个模型调用、工具调用
和子 agent 的耗时、输入输出、模型名与 token 用量，用瀑布图对齐在同一条时间轴上。

选中由桥接服务启动且正在运行的审查或测评轨迹时，详情顶部会出现「停止运行」。点击后会取消对应的
Agent，并清理该次运行的容器；任务完成收尾后显示「已停止」。外部上报的轨迹没有停止按钮。

它的数据**不来自 LangSmith**，而是 agent 侧直接上报的。仓库根目录的 `agent_tracing.py` 是一个
LangChain 回调处理器，把 span 事件批量 POST 给桥接服务；`audit_agent.py` 里已经接好了：

```python
from agent_tracing import tracing_callbacks

result = await agent.ainvoke(payload, config={"callbacks": tracing_callbacks()})
```

它是纯 stdlib 实现、在后台线程里发送，永远不会阻塞或打断 agent：批次按字节切分（默认 8 MB），
发送失败重试三次，仍失败才丢弃并计数，最多每分钟告警一次（`BridgeTracer.stats()` 里的
`dropped` 就是丢掉的条数）。`base_agent.py` 想接的话加同样两行即可。

**载荷完整保真**：span 的输入输出原样上报，不做任何截断（早期的 6000 字符 / 60 项 / 6 层上限
已经移除）。唯一的例外是循环引用的对象——它无法表示成 JSON，会被替换成 `<循环引用>` 标记。

### 树形是怎么还原的

父子关系不能只靠 `parent_run_id`。`LANGSMITH_TRACING=true` 时，langchain 会把每个 middleware 的
`wrap_tool_call` / `wrap_model_call` 包进 `langsmith.traceable(...)`
（见 `langchain/agents/factory.py`）。这层包装 run 只存在于 LangSmith 那一侧，我们的回调处理器
收不到它，于是工具/模型调用报出的 `parentId` 指向一个不存在的节点——轨迹会碎成一堆单 span 的
碎片，把 `MAX_TRACES` 的配额吃掉，真正的树反而被挤出去。

LangGraph 会给**每个** run 打上 `langgraph_step` 和 `langgraph_checkpoint_ns`，包括工具/模型
这些叶子节点，取值与它们所属的节点 run 完全一致。`agent_tracing.py` 的 `_resolve_parent()`
在父节点未知时就改用这对元数据把 span 挂回它的节点，所以 **LangSmith 开着和关着得到的是同一棵树**
（只有需要救助的 span 数量不同）。并行工具调用各自有独立的 `checkpoint_ns`，不会互相串。
实在还原不了的 span 保持孤立，不会被挂到错误的位置上。

agent 和桥接服务跑在同一个容器里，所以 `agent_tracing.py` 默认上报到 `127.0.0.1:8901`
就能直接到达，不需要额外配置。

几个环境变量：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `AGENT_TRACE_URL` | `http://127.0.0.1:<BRIDGE_PORT>/api/agent/events` | 事件上报地址 |
| `AGENT_TRACE_DISABLED` | 未设置 | 设为 `1` 完全关掉上报 |
| `AGENT_TRACE_BATCH_BYTES` | `8388608` | 单批上报的字节上限（载荷整份保留后，不能只按条数切批） |
| `AGENT_TRACE_POST_TIMEOUT_S` | `60` | 单次上报超时 |
| `AGENT_TRACE_QUEUE_MAX` | `8192` | 待发队列上限，满了丢弃并计数（`put_nowait`，绝不阻塞 agent） |
| `AGENT_TRACE_RUNS_MAX` | `50000` | run id 簿记上限（父子推导用） |
| `AGENT_TRACE_MAX_MB` | `384` | 桥接内存里 span 的总预算（仅服务端） |
| `AGENT_TRACE_ARCHIVE` | `<AGENT_TRACE_JOURNAL 的目录>/<文件名去后缀>.archive` | 持久轨迹归档目录（仅服务端） |
| `AGENT_TRACE_JOURNAL` | `<仓库根>/agent_traces.jsonl` | 旧版日志位置，仅用于首次迁移 |
| `AUDIT_TASK_JOURNAL_MAX_MB` | `512` | 审查任务日志轮转阈值（仅服务端） |
| `EVAL_DATASET_ROOT` | `<仓库根>/benchmark` | 数据集目录（仅服务端） |
| `EVAL_JOURNAL_MAX_MB` | `64` | 测评记录日志的轮转阈值（仅服务端） |
| `BRIDGE_PORT` | `8901` | 桥接服务端口，三处共用 |

> 默认端口本来是 8787，但它在不少 Windows 机器上落在系统保留的端口区间里（`netsh int ipv4
> show excludedportrange protocol=tcp` 可以查），会以 `WinError 10013` 绑定失败，所以换成了 8901。
> 改端口要同时改 `web/server/main.py`、`web/vite.config.ts` 和 `agent_tracing.py` 读的 `BRIDGE_PORT`。

### 落盘

轨迹事件先写入持久归档，再向 agent 确认接收。测评和审查任务仍使用各自的日志：

| 数据 | 内存里的上限 | 日志 | 变量 |
| --- | --- | --- | --- |
| agent span 事件（轨迹 / token 用量） | 缓存限 384 MB 或 50 条，不限制历史 | `agent_traces.archive/` | `AGENT_TRACE_ARCHIVE` |
| 审查任务记录 | 最近 50 条任务 | `audit_tasks.jsonl` | `AUDIT_TASK_JOURNAL` |
| 数据集测评记录 | 最近 40 次测评及其样例 | `eval_runs.jsonl` | `EVAL_RUN_JOURNAL` |

每条轨迹的事件写到独立 JSONL 文件，轻量索引保存列表摘要。列表不受内存缓存上限影响；打开一条
已从内存淘汰的轨迹时，桥接服务才从其文件重建 span 树和载荷。`AGENT_TRACE_MAX_MB` 只控制内存
缓存；单条轨迹超过缓存预算时仍可从归档读回完整载荷。每模型调用的 token 记录单独追加在归档中，
重启后也能恢复趋势。

环境检测不在这里：它只有当前这一次读数，留在桥接进程的内存里，没有日志，也没有
`ENV_RUN_JOURNAL` 可配。

首次启动新版桥接服务时，会把现存的 `agent_traces.jsonl.1`、`agent_traces.jsonl` 以及同目录下
`agent_traces.jsonl.saved-*.jsonl` 快照导入归档；重复记录会去重。旧版轮转已覆盖的事件无法恢复。
之后新事件不再写入会覆盖旧文件的轮转日志。归档在项目目录下并已 gitignore；删除轨迹会同时
删除归档、旧日志和这些迁移快照。归档随测评增长，需要保留相应的磁盘空间。

> 用的是 `flush`，**不是 `fsync`** —— 项目目录是 Windows bind mount，`fsync` 在那里会失败
> （`git clone` 就是栽在这）。所以字节会立刻交给操作系统，进程崩溃不丢，但机器断电可能丢最后
> 几笔。要更强的保证就得把日志放到容器原生文件系统（命名卷），代价是不能直接从宿主机看到。

这里也没有示例数据：桥接服务没启动就显示「没有数据」，连上了但还没跑过 agent 就显示
「还没有运行轨迹」。

## 页面结构

每个功能是**独立的一页**，由 `vue-router` 管理，页面对应的 chunk 按需加载，首屏只下载概览。

| 路由 | 页面 | 内容 |
| --- | --- | --- |
| `/overview` | 概览 | Token 用量（总计 + 四项分解）与按小时的使用趋势（各系列独立绘制） |
| `/env-check` | 环境检查 | 「重新检测」按钮 + 检测概览（统计格 + 耗时构成条）+ 每项一张卡片，点开抽屉看原始输出 |
| `/audit` | 漏洞审查 | 切换项目检测 / 函数检测后发起审查任务；任务列表显示拉取/审查状态与结论 |
| `/eval` | 数据集测评 | 选范围（筛选或勾选）→ 批量测评 → 进度、指标与每个样例的判定 |
| `/agent` | Agent 监控 | 运行轨迹列表 + span 瀑布图 |

根路径 `/` 重定向到 `/overview`，未知路径也回落到概览。侧边栏「依赖项」里的每一项都指向
`/env-check#check-<id>`，跨页跳转后会自动滚到对应卡片。

## 目录结构

```
web/
├── src/
│   ├── pages/                      # 每个功能一页
│   │   ├── OverviewPage.vue
│   │   ├── AuditPage.vue           # 漏洞审查
│   │   ├── EvalPage.vue            # 数据集测评
│   │   ├── ChecksPage.vue          # 环境检查
│   │   └── AgentPage.vue
│   ├── router/index.ts             # 路由表，页面对应的 chunk 懒加载
│   ├── components/
│   │   ├── ui/                     # shadcn-vue 组件（由 CLI 生成；Textarea 照同一形状手写）
│   │   ├── dashboard/              # 页面骨架，照 shadcn 的 dashboard-01 排版
│   │   │   ├── AppSidebar.vue          # 侧边栏：品牌、导航、依赖项、页脚状态
│   │   │   ├── NavMain.vue             # 主操作 + 六个页面的导航
│   │   │   ├── NavChecks.vue           # 各依赖及其实时状态
│   │   │   ├── NavSecondary.vue        # 主题切换、复制桥接命令
│   │   │   ├── NavStatus.vue           # 侧边栏页脚：数据源与最近检测
│   │   │   ├── SiteHeader.vue          # 顶栏：折叠按钮、面包屑、数据源
│   │   │   ├── AuditTaskSheet.vue      # 审查任务的完整结论（审查页用）
│   │   │   ├── EvalScopePicker.vue     # 数据集、筛选与勾选、范围预览（测评页用）
│   │   │   ├── EvalRunSheet.vue        # 一次测评的全部指标与每个样例的判定
│   │   │   ├── OverviewStatsCard.vue   # 统计格 + 耗时构成条（环境检查页用）
│   │   │   ├── TraceWaterfall.vue      # span 树的瀑布图（监控页用）
│   │   │   └── SpanDetailsSheet.vue    # 单个 span 的输入输出详情
│   │   ├── CheckCard.vue           # 单个检测项卡片
│   │   ├── CheckDetailsSheet.vue   # 详情抽屉，含原始输出
│   │   └── StatusBadge.vue         # 通过 / 失败 / 检测中 / 未检测
│   ├── composables/
│   │   ├── useEnvironment.ts       # 数据加载、重新检测、清空
│   │   ├── useAgentTraces.ts       # 轨迹列表、选中与轮询
│   │   ├── useAuditTasks.ts        # 审查任务的提交与轮询
│   │   ├── useEvaluation.ts        # 数据集、范围预览、测评列表与轮询
│   │   └── useTheme.ts             # 明暗主题
│   ├── lib/
│   │   ├── traces.ts               # span / 轨迹类型，以及 kind/status 的中文对照
│   │   ├── check-icons.ts          # 后端给的图标名 → lucide 组件
│   │   ├── navigation.ts           # 六个页面的路由 / 标题 / 图标
│   │   ├── api.ts                  # 桥接服务客户端
│   │   └── types.ts / format.ts    # 接口类型、格式化、状态文案
│   └── assets/index.css            # 主题 token（含状态色、图表色、轨迹色）
└── server/
    ├── main.py                     # 可选的 FastAPI 桥接服务
    └── evaluation.py               # 数据集、范围解析、判定与指标（纯逻辑，不碰 git / docker / 模型）
```

## 设计约定

- **版式来自 shadcn 的 `dashboard-01`**：`SidebarProvider` + inset 侧边栏 + `SiteHeader` + 统计卡片行
  + 可切范围的面积图。注意 shadcn-vue 的注册表里**没有**这个 block（只有 UI 组件，没有
  `registry:block`），所以这里是按 React 版的结构用 Vue 组件复刻的，`npx shadcn-vue@latest add
  dashboard-01` 会 404。
- **预设仍是 `reka-nova`**，没有换成 dashboard-01 用的样式。两者的差别主要是圆角和密度；
  如果要完全对齐，需要 `npx shadcn-vue@latest apply --preset <code>` 覆盖现有组件，这一步没有做。
- **前端不存任何内容，一切来自后端。** 每个检查项的名称、传输方式、说明、依赖的环境变量、
  连接目标和图标，都由 `web/server/main.py` 定义并随接口下发；前端原样渲染，自己不留副本。
  拿不到的字段一律显示「没有数据」，桥接服务不可达时整页显示「没有数据 + 无法连接」，而不是
  回退到示例数据。前端的 `mock.ts` / `checks.ts` / `merge.ts` 已全部删除。
- **`.env` 改动无需重启桥接。** 桥接在每次处理请求前重新读取 `.env`，并把当前配置覆盖到最近
  一次运行的测量结果上，所以改了 `MODEL_NAME` 之类的值，刷新页面就能看到。
- **前端只保留 UI 词汇**：按钮文案、导航标题、以及 `pass`/`fail`、`chain`/`model`/`tool` 这类
  枚举到中文的对照表。这些是界面用语，不是数据。
- **状态色与图表色分开**：状态色（通过 / 失败）是固定的、不随明暗主题变化的一组颜色，只用于
  状态，不复用为图表系列色。多系列图表用 `--series-1..5` 这组分类色，顺序固定、不循环，
  颜色跟着检测项走而不是跟着它在图里的排名走（数据变了不会重新配色）。
- **颜色不单独承载信息**：每处状态标记都同时带图标和文字；多系列图表一律配图例和文字标签
  （浅色主题下 `--series-3/4/5` 对比度低于 3:1，图例就是规则要求的补偿）。
- **前端不写图表**：趋势用 shadcn 的 `Chart`（Unovis `VisLine`），图例用 `ChartLegendContent`，
  切换用 `ToggleGroup`，统计格用 `Item`。只有构成条（横向堆叠条）没有对应组件，用几个 div 拼的。
- **明暗两套配色都单独选过**，不是自动反色。切换入口在侧边栏底部。

## 常用命令

```bash
npm run dev            # 开发服务器
npm run build          # 类型检查（vue-tsc）+ 生产构建
npm run preview        # 预览构建产物
```

新增 shadcn-vue 组件：

```bash
npx shadcn-vue@latest add <component>
```
