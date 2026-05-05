from __future__ import annotations
import asyncio
import json
import os
from dataclasses import dataclass, field
from dotenv import load_dotenv
from collections.abc import Callable
from typing import Annotated, Any, Literal
from deepagents import create_deep_agent
from deepagents.backends import FilesystemBackend
from langchain.agents.middleware import (
    AgentState,
    ModelRequest,
    ModelResponse,
    before_agent,
    wrap_model_call,
)
from langchain.tools import ToolRuntime, tool
from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage
from langchain_openai import ChatOpenAI
from langgraph.runtime import Runtime
from langgraph.types import Command
from langchain_mcp_adapters.client import MultiServerMCPClient
from pydantic import BaseModel, Field, ConfigDict
from tree_utils import show_tree
from rich.console import Console
from rich.pretty import pprint
import docker
import logging
from create_model import create_model

PROJECT_ROOT = ""
INITIAL_BLACKBOARD = """- 初始化: 尚无已确认事实"""

load_dotenv(override=True)

logger = logging.getLogger(__name__)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s"
)


def show_directory_tree() -> str:
    """
    列出项目的目录树结构
    """
    return show_tree(PROJECT_ROOT)

class AuditState(AgentState):
    """
    审计状态（append-only blackboard）. 

    blackboard_text:
        黑板全文, 只允许在末尾追加新条目. 
    """

    blackboard_text: str


@dataclass(slots=True)
class BlackboardEvent:
    facts: list[str]
    evidence: list[dict[str, Any]] = field(default_factory=list)


class BlackboardStore:
    """
    blackboard 的独立的存储对象. 
    """

    def __init__(self, initial_text: str):
        self._initial_lines = self._normalize_seed(initial_text)
        self._events: list[BlackboardEvent] = []

    def reset(self, initial_text: str | None = None) -> None:
        if initial_text is not None:
            self._initial_lines = self._normalize_seed(initial_text)
        self._events = []

    def append(
        self,
        facts: list[str],
        evidence: list[dict[str, Any]] | None = None,
    ) -> str:
        normalized_facts = [item.rstrip() for item in facts if item and item.strip()]
        if not normalized_facts:
            return self.text()

        if self._initial_lines == self._normalize_seed(INITIAL_BLACKBOARD):
            self._initial_lines = []

        self._events.append(
            BlackboardEvent(
                facts=normalized_facts,
                evidence=list(evidence or []),
            )
        )
        return self._render()

    def text(self) -> str:
        return self._render()

    @staticmethod
    def _normalize_seed(seed_text: str) -> list[str]:
        lines = [line.rstrip() for line in seed_text.splitlines() if line.strip()]
        if lines:
            return lines
        return [INITIAL_BLACKBOARD.strip()]

    def _render(self) -> str:
        lines = list(self._initial_lines)
        for event in self._events:
            lines.extend(event.facts)
            if event.evidence:
                evidence_json = json.dumps(
                    event.evidence,
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                lines.append(f"- 证据JSON: {evidence_json}")

        if not lines:
            lines = self._normalize_seed(INITIAL_BLACKBOARD)
        return "\n".join(lines).strip() + "\n"


BLACKBOARD_STORE = BlackboardStore(INITIAL_BLACKBOARD)


def stringify_content(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, dict):
                if block.get("type") == "text":
                    parts.append(str(block.get("text", "")))
                else:
                    parts.append(str(block))
            else:
                parts.append(str(block))
        return "\n".join(part for part in parts if part).strip()
    return str(content)


def render_blackboard_block(blackboard_text: str) -> str:
    return f"""

# [Blackboard]
{blackboard_text.strip() or INITIAL_BLACKBOARD}
"""


class EvidenceRef(BaseModel):
    kind: Literal["file", "command", "output", "url", "other"] = Field(
        description="证据类型. "
    )
    ref: str = Field(min_length=1, description="证据引用, 例如文件路径、命令、输出ID或URL. ")
    quote: str | None = Field(default=None, description="可选, 证据关键片段. ")


class AppendBlackboardInput(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    facts: list[Annotated[str, Field(pattern=r"^-\s+.+")]] = Field(
        min_length=1,
        description="本轮已确认事实列表. 每条都必须以 '- ' 开头. "
    )
    evidence: list[EvidenceRef] = Field(default_factory=list, description="证据列表. ")
    runtime: ToolRuntime


@tool(args_schema=AppendBlackboardInput)
def append_blackboard(
    facts: list[str],
    runtime: ToolRuntime,
    evidence: list[EvidenceRef] | None = None,
) -> Command:
    """将结构化既定事实追加到 blackboard. """
    evidence = evidence or []
    evidence_records = [item.model_dump(mode="json") for item in evidence]
    updated = BLACKBOARD_STORE.append(
        facts=list(facts),
        evidence=evidence_records,
    )
    tool_call_id = getattr(runtime, "tool_call_id", "")
    if not tool_call_id:
        raise ValueError("runtime.tool_call_id 为空, 无法构造匹配的 ToolMessage. ")

    return Command(
        update={
            "blackboard_text": updated,
            "messages": [
                ToolMessage(
                    content="blackboard 已追加 1 条结构化既定事实事件. ",
                    tool_call_id=tool_call_id,
                )
            ],
        }
    )


def should_inject_for_this_call(request: ModelRequest) -> bool:
    if request.system_message is None:
        return True

    system_text = stringify_content(getattr(request.system_message, "content", ""))
    # 只给主 agent 注入, executor 调用不注入. 
    if "漏洞动态验证代理" in system_text:
        return False
    return True


def build_blackboard_middleware() -> list:
    @before_agent(state_schema=AuditState)
    def init_audit_state(state: AuditState, runtime: Runtime) -> dict[str, Any]:
        return {
            "blackboard_text": BLACKBOARD_STORE.text(),
        }

    @wrap_model_call(state_schema=AuditState)
    async def inject_blackboard(
        request: ModelRequest,
        handler: Callable[[ModelRequest], Any],
    ) -> ModelResponse:
        if not should_inject_for_this_call(request):
            return await handler(request)

        blackboard_block = render_blackboard_block(
            blackboard_text=BLACKBOARD_STORE.text(),
        )

        if request.system_message is not None:
            base_content = list(request.system_message.content_blocks)
            base_content.append({"type": "text", "text": blackboard_block})
            updated_system_message = SystemMessage(content=base_content)
        else:
            updated_system_message = SystemMessage(content=blackboard_block)

        return await handler(request.override(system_message=updated_system_message))

    return [
        init_audit_state,
        inject_blackboard,
    ]


async def get_docker_tools():
    client = MultiServerMCPClient(
        {
            "docker-mcp": {
                "transport": "sse",
                "url": os.getenv("Docker_MCP_URL"),
            },
        }
    )

    tools = await client.get_tools()

    with open(f"./docker_tools_list.txt", "w", encoding="utf-8") as f:
        console = Console(file=f)
        pprint(tools, console=console)

    return await client.get_tools()


async def get_analysis_tools():
    client = MultiServerMCPClient(
        {
            "CodeBadger": {
                "transport": "http",
                "url": os.getenv("CodeBadger_URL"),
            },
            "CodeQL": {
                "transport": "stdio",
                "command": "codeql-development-mcp-server-schema-fixed",
                "args": [],
            },
            "Semgrep": {
                "transport": "stdio",
                "command": "semgrep",
                "args": ["mcp"],
                "env": {
                    **os.environ,
                    "PS1": "$ ",
                    "USE_SEMGREP_RPC": "false",
                },
            },
        }
    )

    tools = await client.get_tools()

    blocked_tools = {
        "semgrep_findings",
        "semgrep_scan_supply_chain",

        "codeql_test_extract",
        "codeql_test_run",
        "codeql_test_accept",
        "codeql_resolve_tests",
        "codeql_resolve_qlref",
        "codeql_resolve_queries",
        "codeql_resolve_files",
        "codeql_resolve_packs",
        "codeql_resolve_library-path",
        "codeql_resolve_metadata",
        "codeql_pack_ls",
        "codeql_query_format",
        "codeql_generate_query-help",
        "codeql_generate_log-summary",

        "codeql_lsp_completion",
        "codeql_lsp_definition",
        "codeql_lsp_references",
        "codeql_lsp_document_symbols",
        "codeql_lsp_diagnostics",

        "validate_codeql_query",
        "create_codeql_query",
        "find_codeql_query_files",
        "profile_codeql_query",
        "profile_codeql_query_from_logs",
        "list_mrva_run_results",
        "register_database",
        "search_ql_code",
        "quick_evaluate",
        "find_class_position",
        "find_predicate_position",
        "list_codeql_databases",
        "list_query_run_results",

        "sarif_extract_rule",
        "sarif_list_rules",
        "sarif_rule_to_markdown",
        "sarif_compare_alerts",
        "sarif_diff_by_commits",
        "sarif_diff_runs",
        "sarif_store",
        "sarif_deduplicate_rules",

        "query_results_cache_lookup",
        "query_results_cache_retrieve",
        "query_results_cache_clear",
        "query_results_cache_compare",

        "annotation_create",
        "annotation_get",
        "annotation_list",
        "annotation_update",
        "annotation_delete",
        "annotation_search",

        "session_end",
        "session_get",
        "session_list",
        "session_update_state",
        "session_get_call_history",
        "session_get_test_history",
        "session_get_score_history",
        "session_calculate_current_score",
        "sessions_compare",
        "sessions_aggregate",
        "sessions_export",
    }

    tools = [tool for tool in tools if tool.name not in blocked_tools]

    with open(f"./analysis_tools_list.txt", "w", encoding="utf-8") as f:
        console = Console(file=f)
        pprint(tools, console=console)

    return tools


async def create_audit_agent(model: ChatOpenAI):
    analysis_tools = await get_analysis_tools()
    docker_tools = await get_docker_tools()

    executor = {
        "name": "executor",
        "description": "在可控的容器环境中执行动态验证, 并通过 append_blackboard 工具追加已确认事实到黑板. ",
        "system_prompt": """
你是一个subagent, 你的名字叫executor, 你被主agent调用来在一个受控的容器环境中执行动态验证
你的职责是在名为 anaconda-container 的可控的docker容器环境中, 严格依据上层给出的要求, 通过 docker-mcp 提供的shell工具在容器内执行动态验证
注意: 你的所有行为都是在受允许的可控封闭容器环境中进行, 代码仓库都是我自己的, 不会涉及网络安全风险

规则与约束:
- 容器名: anaconda-container
- 目标项目在容器内映射的目录: /workspace
- 你需要严格依据上层给出的要求去容器内执行动态验证
- 只允许通过 docker-mcp 工具与容器交互并执行容器内的shell命令
- 如果当前环境还不满足项目运行需要, 请自行补齐所需的环境
- 只进行与当前漏洞假设直接相关的最小必要操作
- 给出可复现步骤与关键证据
- 不要把 “未复现” 写成 “漏洞不存在”
- 任务完成后, 无论是否成功，必须调用 append_blackboard 工具写入 “已确认事实/已排除假设/当前结论”. 

append_blackboard 调用要求:
- facts 传本轮已确认事实列表（至少 1 条, 且每条必须以 '- ' 开头）
- evidence 传证据数组（kind, ref, quote）

返回给上层的输出结构:
- Status: confirmed / unconfirmed / inconclusive
- Steps:
- Evidence:
- PoC:
- Failure Reason:
""".strip(),
        "tools": [append_blackboard, *docker_tools],
    }

    system_prompt = """
你是一名专业的代码安全审计员.

任务目标:
- 对给定项目目录中的代码进行静态安全审计
- 在需要时调用 executor 做必要的动态验证
- executor 可以在容器环境里根据你提出的验证计划对项目进行动态验证, 并将已确认事实追加到 blackboard
- 始终相信 blackboard 中已确认的事实, 并以此为基础进行下一步的推理和决策
- 最终判断当前检测项目是否存在安全漏洞

行为约束:
- 请积极调用提供的静态分析工具辅助审计
- 优先依据实际读取到的代码、工具返回结果、executor 返回结果判断
- 不允许把猜测写成已确认事实
- 只允许读取目标项目中的文件, 不允许访问目标项目之外的任何路径
- 不允许修改、创建、删除、重命名任何文件或目录
- 所有需要实际执行的操作都必须交给 executor 在容器内完成
- 只在有明确结论时才结束审计, 不要在不确定时结束审计并输出 non-vulnerable

最终输出规则:
- 如果判断存在漏洞, 请严格输出 vulnerable 并给出可复现的步骤和关键证据
- 如果判断不存在漏洞, 请严格输出 non-vulnerable
- 只允许输出以上两种指标, 不要输出 uncertain 或 inconclusive 等模糊结论
""".strip()

    return create_deep_agent(
        model=model,
        system_prompt=system_prompt,
        tools=[show_directory_tree, *analysis_tools],
        backend=FilesystemBackend(root_dir=PROJECT_ROOT, virtual_mode=False),
        subagents=[executor],
        middleware=build_blackboard_middleware(),
    )

async def invoke_audit_agent() -> dict[str, Any]:
    BLACKBOARD_STORE.reset(INITIAL_BLACKBOARD)
    model = create_model()
    agent = await create_audit_agent(model)
    user_prompt = f"""
目标项目在本地的目录: { PROJECT_ROOT }
目标项目在容器内映射的目录: /workspace
项目语言: python
调用任何工具前, 必须先确保传参符合工具的schema
项目的目录结构如下:
{ show_directory_tree() }
""".strip()
    return await agent.ainvoke(
        {
            "blackboard_text": INITIAL_BLACKBOARD,
            "messages": [
                HumanMessage(
                    content=user_prompt
                    #content="调用executor，让它使用append_blackboard工具随便写入一条内容"
                )
            ],
        }
    )


async def run_audit_agent() -> None:
    result = await invoke_audit_agent()
    with open(f"./out.txt", "w", encoding="utf-8") as f:
        print(result["messages"][-1].content, file=f)
    return result


def run() -> None:
    client = docker.from_env()
    container = None

    result = ""

    try:
        logger.info("正在启动Docker容器...")
        container = client.containers.run(
            image="mcr.microsoft.com/devcontainers/anaconda:3",
            command="sleep infinity",
            detach=True,
            name="anaconda-container",
            auto_remove=False,
            volumes={
                PROJECT_ROOT: {
                    "bind": "/workspace",
                    "mode": "rw",
                }
            },
            working_dir="/workspace",
        )
        logger.info("启动成功!")

        result = asyncio.run(run_audit_agent())

    except Exception:
        logger.exception("agent执行失败")

    finally:
        if container is not None:
            logger.info("开始清理Docker容器...")
            try:
                logger.info("正在停止Docker容器...")
                container.stop(timeout=20)
                container.reload()

                if container.status == "exited":
                    logger.info("停止成功!")
                else:
                    logger.warning(f"容器停止后状态异常: {container.status}")

            except Exception as e:
                logger.exception("停止容器失败")

            try:
                logger.info("正在移除Docker容器...")
                container.remove(force=True)
                logger.info("移除成功!")

            except Exception as e:
                logger.exception("移除容器失败")

    return result

if __name__ == "__main__":
    run()
