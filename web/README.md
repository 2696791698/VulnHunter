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

容器内先补一个依赖（桥接服务自己需要，不在项目依赖里）：

```bash
uv pip install --python /home/vscode/.venv/bin/python fastapi
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

几个由 `audit_agent.run()` 的现状决定的设计：

- **一次只跑一个。** `run()` 起的是固定名字的 `anaconda-container`，而且读模块级全局的
  `PROJECT_ROOT`，所以任务由**单个工作线程**按队列串行处理。
- **必须在工作线程里跑。** `run()` 内部调用 `asyncio.run()`，不能在请求的事件循环里嵌套调用。
- **检出目录放在容器原生路径**（默认 `/home/vscode/audits/<task-id>`，`AUDIT_ROOT` 可改）。
  项目目录是 Windows bind mount，`git` 往那里写 pack 文件会 `fsync` 失败。检出本身可以用
  url + commit 重新克隆，放在临时存储里没有代价；任务记录才需要持久化。
- **地址和 ref 都做白名单校验**（`URL_PATTERN` / `REF_PATTERN`），并且用 argv 数组调 git
  （从不过 shell）。以 `-` 开头的 ref 会被拒绝，避免被当成 git 参数。

任务状态变化会立刻追加到 `audit_tasks.jsonl`（同样已 gitignore、同样在超限时轮转），
所以重启服务后列表还在；上次进程被杀时停在「进行中」的任务，回放时会标成失败并说明原因。

## Agent 监控

「Agent 监控」区块按 LangSmith 的方式展示一次 agent 运行的 span 树：每个模型调用、工具调用
和子 agent 的耗时、输入输出、模型名与 token 用量，用瀑布图对齐在同一条时间轴上。

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
| `AGENT_TRACE_JOURNAL_MAX_MB` | `512` | 日志轮转阈值（仅服务端） |
| `AGENT_TRACE_REPLAY_MB` | `128` | 启动时回放的日志尾部上限（仅服务端） |
| `BRIDGE_PORT` | `8901` | 桥接服务端口，三处共用 |

> 默认端口本来是 8787，但它在不少 Windows 机器上落在系统保留的端口区间里（`netsh int ipv4
> show excludedportrange protocol=tcp` 可以查），会以 `WinError 10013` 绑定失败，所以换成了 8901。
> 改端口要同时改 `web/server/main.py`、`web/vite.config.ts` 和 `agent_tracing.py` 读的 `BRIDGE_PORT`。

### 落盘

**两类数据都实时写盘，重启服务不会丢**，启动时各自回放进内存：

| 数据 | 内存里的上限 | 日志 | 变量 |
| --- | --- | --- | --- |
| agent span 事件（轨迹 / token 用量） | 384 MB 或 50 条轨迹，先到先算 | `agent_traces.jsonl` | `AGENT_TRACE_JOURNAL` |
| 审查任务记录 | 最近 50 条任务 | `audit_tasks.jsonl` | `AUDIT_TASK_JOURNAL` |

载荷现在整份保留，所以 span 存储按**字节**而不是条数设上限（`AGENT_TRACE_MAX_MB`，默认
384 MB）：超预算时整条轨迹从旧到新淘汰；万一单次审计本身就超预算，就释放这条轨迹里最旧 span
的载荷而保留 span 本身——树形和耗时不受影响，被释放的载荷会在详情里写明原因。token 用量另外
存一份极小的每模型调用记录，不受淘汰影响；否则内存一收紧，概览的趋势图就会跟着断掉。

环境检测不在这里：它只有当前这一次读数，留在桥接进程的内存里，没有日志，也没有
`ENV_RUN_JOURNAL` 可配。

写入方式是追加一行 JSON，然后 `write` + `flush`；日志超过 `AGENT_TRACE_JOURNAL_MAX_MB`（默认
512 MB）时轮转到 `.jsonl.1`（覆盖上一份）。轮转在**写入时**判断，不只在启动阶段——一次审计
就能让文件涨几十 MB。启动时只回放日志尾部（`AGENT_TRACE_REPLAY_MB`，默认 128 MB），超出的
部分本来也会被内存预算淘汰，读进来再扔掉没有意义。日志落在项目目录下（已 gitignore）
—— 那是容器重建后唯一还在的地方。

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
│   │   ├── ChecksPage.vue          # 环境检查
│   │   └── AgentPage.vue
│   ├── router/index.ts             # 路由表，页面对应的 chunk 懒加载
│   ├── components/
│   │   ├── ui/                     # shadcn-vue 组件（由 CLI 生成；Textarea 照同一形状手写）
│   │   ├── dashboard/              # 页面骨架，照 shadcn 的 dashboard-01 排版
│   │   │   ├── AppSidebar.vue          # 侧边栏：品牌、导航、依赖项、页脚状态
│   │   │   ├── NavMain.vue             # 主操作 + 五个页面的导航
│   │   │   ├── NavChecks.vue           # 各依赖及其实时状态
│   │   │   ├── NavSecondary.vue        # 主题切换、复制桥接命令
│   │   │   ├── NavStatus.vue           # 侧边栏页脚：数据源与最近检测
│   │   │   ├── SiteHeader.vue          # 顶栏：折叠按钮、面包屑、数据源
│   │   │   ├── AuditTaskSheet.vue      # 审查任务的完整结论（审查页用）
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
│   │   └── useTheme.ts             # 明暗主题
│   ├── lib/
│   │   ├── traces.ts               # span / 轨迹类型，以及 kind/status 的中文对照
│   │   ├── check-icons.ts          # 后端给的图标名 → lucide 组件
│   │   ├── navigation.ts           # 五个页面的路由 / 标题 / 图标
│   │   ├── api.ts                  # 桥接服务客户端
│   │   └── types.ts / format.ts    # 接口类型、格式化、状态文案
│   └── assets/index.css            # 主题 token（含状态色、图表色、轨迹色）
└── server/main.py                  # 可选的 FastAPI 桥接服务
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
