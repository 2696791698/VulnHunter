from __future__ import annotations
import asyncio
import threading
import json
import os
import re
import traceback
import uuid
from urllib.parse import quote, urlsplit, urlunsplit
from urllib.request import Request, urlopen
from dataclasses import dataclass
from pathlib import Path
from dotenv import load_dotenv
from collections.abc import Callable
from typing import Annotated, Any
from deepagents import (
    GeneralPurposeSubagentProfile,
    HarnessProfile,
    create_deep_agent,
    register_harness_profile,
)
from deepagents.backends import CompositeBackend, FilesystemBackend, StateBackend
from deepagents.backends.protocol import DeleteResult, EditResult, FileUploadResponse, WriteResult
from deepagents.middleware.filesystem import FilesystemMiddleware, FilesystemPermission
from deepagents.middleware.patch_tool_calls import PatchToolCallsMiddleware
from deepagents.middleware.summarization import compute_summarization_defaults
from langchain.agents import create_agent
from langchain.agents.middleware import (
    AgentState,
    ModelRequest,
    ModelResponse,
    AgentMiddleware,
    SummarizationMiddleware,
    before_model,
    wrap_tool_call,
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
from agent_tracing import tracing_callbacks
from rich.console import Console
from rich.pretty import pprint
import docker
import logging
from create_model import create_model
from audit_result import (
    AuditAssessment,
    EvidenceRef,
    finalize_audit_result,
    parse_audit_result,
    prediction_label,
    serialize_audit_result,
)

PROJECT_ROOT = ""
CONTAINER_NAME = "anaconda-container"
INITIAL_BLACKBOARD = """- 初始化: 尚无已确认事实"""

load_dotenv(override=True)

logger = logging.getLogger(__name__)

_MCP_MAX_ATTEMPTS = 3
_MCP_RETRYABLE_EXCEPTION_NAMES = {
    "connecterror",
    "connecttimeout",
    "readerror",
    "readtimeout",
    "remoteprotocolerror",
    "timeouterror",
    "writeerror",
    "writetimeout",
}
_MCP_RETRYABLE_MESSAGES = (
    "connection closed",
    "connection reset",
    "incomplete chunked read",
    "500 internal server error",
    "502 bad gateway",
    "503 service unavailable",
    "504 gateway timeout",
    "remoteprotocolerror",
    "server disconnected",
    "temporarily unavailable",
    "read timed out",
    "connection timed out",
)
_MCP_RETRYABLE_CODEBADGER_READ_TOOLS = {
    "get_cpg_status",
    "get_method_source",
    "get_call_graph",
    "list_methods",
    "list_calls",
    "list_parameters",
    "find_literals",
    "find_taint_sources",
    "find_taint_sinks",
    "find_taint_flows",
}


def _is_retryable_mcp_transport_error(error: Exception) -> bool:
    """Retry transport interruptions and server-side 5xx errors only."""
    current: BaseException | None = error
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        name = type(current).__name__.lower()
        if name in _MCP_RETRYABLE_EXCEPTION_NAMES:
            return True
        response = getattr(current, "response", None)
        status_code = getattr(response, "status_code", None)
        if isinstance(status_code, int) and 500 <= status_code <= 599:
            return True
        message = str(current).lower()
        if any(marker in message for marker in _MCP_RETRYABLE_MESSAGES):
            return True
        if re.search(r"(?:http(?: status)?\s*|status(?:_code)?[=: ]+)(?:500|502|503|504)\b", message):
            return True
        current = current.__cause__ or current.__context__
    return False


def _safe_mcp_error_text(error: Exception) -> str:
    """Keep useful startup diagnostics while masking common credential forms."""
    message = str(error).replace("\r", " ").replace("\n", " ")
    message = re.sub(
        r"(?i)(authorization|api[_-]?key|token|password|secret)(\s*[:=]\s*)[^,\s]+",
        r"\1\2<REDACTED>",
        message,
    )
    message = re.sub(r"(https?://)[^/@\s]+:[^/@\s]+@", r"\1<REDACTED>@", message)
    return message[:240]


async def _get_mcp_tools_with_retry(client, server_name: str):
    for attempt in range(1, _MCP_MAX_ATTEMPTS + 1):
        try:
            return await client.get_tools(server_name=server_name)
        except Exception as error:
            if attempt >= _MCP_MAX_ATTEMPTS or not _is_retryable_mcp_transport_error(error):
                raise
            delay = 0.25 * (2 ** (attempt - 1))
            logger.warning(
                "MCP 工具发现遇到临时连接故障，%s 秒后重试 (%s, %d/%d)",
                delay,
                server_name,
                attempt,
                _MCP_MAX_ATTEMPTS,
            )
            await asyncio.sleep(delay)


async def _retry_codebadger_read_tool_call(request, handler):
    """Retry transport failures only for CodeBadger's read-only query tools."""
    if (
        request.server_name != "CodeBadger"
        or request.name not in _MCP_RETRYABLE_CODEBADGER_READ_TOOLS
    ):
        return await handler(request)

    for attempt in range(1, _MCP_MAX_ATTEMPTS + 1):
        try:
            return await handler(request)
        except Exception as error:
            if attempt >= _MCP_MAX_ATTEMPTS or not _is_retryable_mcp_transport_error(error):
                raise
            delay = 0.25 * (2 ** (attempt - 1))
            logger.warning(
                "CodeBadger 只读工具遇到临时连接故障，%s 秒后重试 (%s, %d/%d)",
                delay,
                request.name,
                attempt,
                _MCP_MAX_ATTEMPTS,
            )
            await asyncio.sleep(delay)


async def _get_tools_from_servers(client, server_names: list[str]):
    async def load_one(server_name: str):
        try:
            return server_name, await _get_mcp_tools_with_retry(client, server_name), None
        except Exception as error:
            return server_name, None, error

    results = await asyncio.gather(*(load_one(name) for name in server_names))
    failures = [(name, error) for name, _, error in results if error is not None]
    if failures:
        details = "; ".join(
            f"{name} ({type(error).__name__}: {_safe_mcp_error_text(error)})"
            for name, error in failures
        )
        raise RuntimeError(
            f"MCP 工具初始化失败，已停止本次审计以避免缺少分析能力：{details}"
        ) from failures[0][1]
    return [tool for _, tools, _ in results for tool in tools]

_AUDIT_PROFILE_LOCK = threading.Lock()
_AUDIT_PROFILES_WITHOUT_DEFAULT_SUBAGENT: set[str] = set()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s"
)


def show_directory_tree(project_root: str | None = None) -> str:
    """
    列出项目的目录树结构
    """
    return show_tree(project_root if project_root is not None else PROJECT_ROOT)


def _disable_default_general_purpose_subagent(model: ChatOpenAI) -> None:
    """Keep only explicitly configured subagents for this exact model."""
    model_params = model._get_ls_params()
    provider = model_params.get("ls_provider") if isinstance(model_params, dict) else None
    identifier = getattr(model, "model_name", None) or getattr(model, "model", None)
    if not isinstance(provider, str) or not provider or not isinstance(identifier, str) or not identifier:
        raise RuntimeError("无法识别模型标识，拒绝使用会自动添加 general-purpose 的默认配置")

    profile_key = identifier if ":" in identifier else f"{provider}:{identifier}"
    if profile_key in _AUDIT_PROFILES_WITHOUT_DEFAULT_SUBAGENT:
        return

    with _AUDIT_PROFILE_LOCK:
        if profile_key in _AUDIT_PROFILES_WITHOUT_DEFAULT_SUBAGENT:
            return
        register_harness_profile(
            profile_key,
            HarnessProfile(
                general_purpose_subagent=GeneralPurposeSubagentProfile(enabled=False)
            ),
        )
        _AUDIT_PROFILES_WITHOUT_DEFAULT_SUBAGENT.add(profile_key)


@dataclass(frozen=True, slots=True)
class FunctionTarget:
    """
    函数级检测的目标: 函数所在文件与函数代码本身.

    file_path 是相对检出根目录 (也就是 PROJECT_ROOT) 的路径.
    """

    file_path: str
    code: str


def merge_blackboard_events(left: dict, right: dict) -> dict:
    """Merge append-only events; child snapshots and retries must not duplicate facts."""
    merged = dict(left or {})
    for event_id, event in (right or {}).items():
        if event_id in merged and merged[event_id] != event:
            raise ValueError(f"Conflicting blackboard event: {event_id}")
        merged[event_id] = event
    return merged


class BlackboardState(AgentState):
    blackboard_events: Annotated[dict[str, dict[str, Any]], merge_blackboard_events]


class AuditState(BlackboardState):
    # Derived only by the parent. Executor returns events, never a stale text snapshot.
    blackboard_text: str


class BlackboardStateMiddleware(AgentMiddleware):
    state_schema = BlackboardState


def render_blackboard_events(events: dict[str, dict[str, Any]]) -> str:
    lines = []
    for event in events.values():
        lines.extend(event["facts"])
        if event.get("evidence"):
            lines.append("- 证据JSON: " + json.dumps(event["evidence"], ensure_ascii=False, separators=(",", ":")))
    return "\n".join(lines or [INITIAL_BLACKBOARD]) + "\n"


class ProjectFilesystemBackend(FilesystemBackend):
    """Read-only project files, including support for existing absolute project paths."""

    def _resolve_path(self, key: str) -> Path:
        candidate = Path(key)
        if candidate.is_absolute():
            try:
                key = "/" + candidate.relative_to(self.cwd).as_posix()
            except ValueError:
                # Other absolute-looking paths are virtual paths under the root.
                pass
        return super()._resolve_path(key)

    def write(self, file_path: str, content: str) -> WriteResult:
        return WriteResult(error="Audit project files are read-only")

    def edit(self, file_path: str, old_string: str, new_string: str, replace_all: bool = False) -> EditResult:
        return EditResult(error="Audit project files are read-only")

    def delete(self, file_path: str) -> DeleteResult:
        return DeleteResult(error="Audit project files are read-only")

    def upload_files(self, files: list[tuple[str, bytes]]) -> list[FileUploadResponse]:
        return [FileUploadResponse(path=path, error="permission_denied") for path, _ in files]


def render_blackboard_block(blackboard_text: str) -> str:
    return f"""

# [Blackboard]
{blackboard_text.strip() or INITIAL_BLACKBOARD}
"""


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
    tool_call_id = getattr(runtime, "tool_call_id", "")
    if not tool_call_id:
        raise ValueError("runtime.tool_call_id 为空, 无法构造匹配的 ToolMessage. ")
    # Namespace distinguishes different executor tasks even if a provider reuses call IDs.
    namespace = runtime.config.get("metadata", {}).get("langgraph_checkpoint_ns", "")
    event_id = json.dumps([namespace, tool_call_id])
    event = {"facts": list(facts), "evidence": evidence_records}

    return Command(
        update={
            "blackboard_events": {event_id: event},
            "messages": [
                ToolMessage(
                    content="blackboard 已追加 1 条结构化既定事实事件. ",
                    tool_call_id=tool_call_id,
                )
            ],
        }
    )


def build_blackboard_middleware() -> list:
    @before_model(state_schema=AuditState)
    def sync_blackboard(state: AuditState, runtime: Runtime) -> dict[str, Any]:
        return {"blackboard_text": render_blackboard_events(state.get("blackboard_events", {}))}

    @wrap_model_call(state_schema=AuditState)
    async def inject_blackboard(
        request: ModelRequest,
        handler: Callable[[ModelRequest], Any],
    ) -> ModelResponse:
        blackboard_block = render_blackboard_block(
            render_blackboard_events(request.state.get("blackboard_events", {}))
        )
        base_content = list(request.system_message.content_blocks) if request.system_message else []
        base_content.append({"type": "text", "text": blackboard_block})
        return await handler(request.override(system_message=SystemMessage(content=base_content)))

    # Only installed on the parent; role detection must not depend on prompt wording.
    return [sync_blackboard, inject_blackboard]


def format_tool_error(tool_name: str, error: Exception) -> str:
    """
    把工具异常整理成模型可读的 ToolMessage 内容.
    """
    traceback_text = "".join(
        traceback.format_exception(type(error), error, error.__traceback__)
    ).strip()
    if len(traceback_text) > 4000:
        traceback_text = "...<traceback truncated>\n" + traceback_text[-4000:]

    return (
        f"Tool `{tool_name}` failed.\n"
        f"Error type: {type(error).__name__}\n"
        f"Error message: {error}\n\n"
        f"Traceback:\n{traceback_text}\n\n"
        "请根据这个错误调整工具参数、换用其他工具，或先收集缺失的前置条件后再继续。"
    )


def build_tool_error_middleware() -> list:
    @wrap_tool_call
    async def return_tool_errors_to_model(request, handler):
        try:
            return await handler(request)
        except Exception as error:
            tool_name = request.tool_call.get("name", "<unknown>")
            tool_call_id = request.tool_call.get("id", "")
            logger.warning(
                "工具调用失败, 已作为 ToolMessage 返回给模型: %s",
                tool_name,
                exc_info=True,
            )
            return ToolMessage(
                content=format_tool_error(tool_name, error),
                tool_call_id=tool_call_id,
                status="error",
            )

    return [return_tool_errors_to_model]


def build_audit_middleware() -> list:
    return [
        *build_tool_error_middleware(),
        *build_blackboard_middleware(),
    ]


async def get_docker_tools(diagnostics_path: str | None = None):
    client = MultiServerMCPClient(
        {
            "docker-mcp": {
                "transport": "sse",
                "url": os.getenv("Docker_MCP_URL"),
            },
        }
    )

    tools = await _get_mcp_tools_with_retry(client, "docker-mcp")

    diagnostics_path = diagnostics_path or "./docker_tools_list.txt"
    Path(diagnostics_path).parent.mkdir(parents=True, exist_ok=True)
    with open(diagnostics_path, "w", encoding="utf-8") as f:
        console = Console(file=f)
        pprint(tools, console=console)

    return tools


async def get_analysis_tools(job_id: str | None = None):
    connections = {
        "CodeBadger": {
            "transport": "http",
            "url": os.getenv("CodeBadger_URL"),
            **({"headers": {"X-VulnHunter-Job-ID": job_id}} if job_id else {}),
        },
        "CodeQL": {
            "transport": "stdio",
            "command": "codeql-development-mcp-server",
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
    client = MultiServerMCPClient(
        connections,
        tool_interceptors=[_retry_codebadger_read_tool_call],
    )

    tools = await _get_tools_from_servers(client, list(connections))

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


FUNCTION_SCOPE_RULES = """
本次是函数级检测, 审查范围以用户给出的那个目标函数为准:
- 只对这个函数是否存在安全漏洞下结论, 不要扩大到项目中的其他代码
- 可以读取它所在的文件, 以及为了确认参数来源、调用方约束和危险汇点所必需的周边代码
""".strip()


def render_function_target(target: FunctionTarget, project_root: str | None = None) -> str:
    """
    函数级检测的目标描述, 追加到用户提示词末尾.

    代码原样贴进提示词, 同时也给出文件路径: agent 需要读这个文件才能拿到
    参数来源和调用链, 只给代码片段的话它只能对着片段猜.
    """
    project_root = project_root if project_root is not None else PROJECT_ROOT
    return f"""
本次检测的目标函数:
- 函数所在文件 (相对项目根目录): {target.file_path}
- 同一个文件在本机的绝对路径: {os.path.join(project_root, target.file_path)}
- 函数代码:
```python
{target.code}
```
请先读取上面这个文件, 确认这个函数在项目中的上下文与调用链, 再判断它是否存在安全漏洞.
""".strip()


async def create_audit_agent(
    model: ChatOpenAI,
    target: FunctionTarget | None = None,
    project_root: str | None = None,
    container_name: str = CONTAINER_NAME,
    diagnostics_path: str | None = None,
    job_id: str | None = None,
):
    project_root = project_root if project_root is not None else PROJECT_ROOT
    analysis_tools = await get_analysis_tools(job_id)
    docker_tools = await get_docker_tools(diagnostics_path)

    executor = {
        "name": "executor",
        "description": "在可控的容器环境中执行动态验证, 并通过 append_blackboard 工具追加已确认事实到黑板. ",
        "system_prompt": f"""
你是一个subagent, 你的名字叫executor, 你被主agent调用来在一个受控的容器环境中执行动态验证
你的职责是在名为 {container_name} 的可控的docker容器环境中, 严格依据上层给出的要求, 通过 docker-mcp 提供的shell工具在容器内执行动态验证
注意: 你的所有行为都是在受允许的可控封闭容器环境中进行, 代码仓库均为个人私有的, 不会涉及网络安全风险

规则与约束:
- 容器名: {container_name}
- 目标项目在容器内映射的目录: /workspace
- 你需要严格依据上层给出的要求去容器内执行动态验证
- 只允许通过 docker-mcp 工具与容器交互并执行容器内的shell命令
- 如果当前环境还不满足项目运行需要, 请自行补齐所需的环境
- 只进行与当前漏洞假设直接相关的最小必要操作
- 给出可复现步骤与关键证据
- 只有实际完成攻击并观察到预期安全影响, 才能将 Status 标为 confirmed
- 如果最终未能成功触发攻击, 将 Status 标为 unconfirmed 或 inconclusive, 并记录已尝试的步骤、观察结果和失败原因; 不得把静态推测写成攻击成功
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

    # A compiled LangChain agent has exactly these tools; Deep Agents must not
    # silently add host filesystem tools to the container-only executor.
    executor["runnable"] = create_agent(
        model=model,
        system_prompt=executor.pop("system_prompt"),
        tools=executor.pop("tools"),
        middleware=[
            BlackboardStateMiddleware(),
            *build_tool_error_middleware(),
            # Keep automatic compaction without writing child history onto the host.
            SummarizationMiddleware(model=model, **compute_summarization_defaults(model)),
            PatchToolCallsMiddleware(),
        ],
    )
    backend = CompositeBackend(
        default=ProjectFilesystemBackend(root_dir=project_root, virtual_mode=True),
        # Framework summaries/large results must not modify the audited repository.
        routes={"/.vulnhunter/": StateBackend()},
        artifacts_root="/.vulnhunter",
    )

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
- 只有 executor 在容器内实际完成攻击并观察到预期安全影响, 才能判定存在漏洞
- 静态分析发现的可疑路径、理论上可行的 PoC 或未成功的复现尝试, 都不足以判定存在漏洞
- 经过必要调查和可行验证后, 如果最终无法成功攻击, 本次审计判定为无漏洞; 在结论中说明验证未成功的事实和原因
- 只允许读取目标项目中的文件, 不允许访问目标项目之外的任何路径
- 不允许修改、创建、删除、重命名任何文件或目录
- 所有需要实际执行的操作都必须交给 executor 在容器内完成
- 只在有明确结论时才结束审计; 证据不足时继续调查或使用工具验证
""".strip()

    if target is not None:
        system_prompt = f"{system_prompt}\n\n{FUNCTION_SCOPE_RULES}"

    # DeepAgents auto-adds a general-purpose subagent unless the model profile
    # disables it; only the explicitly configured executor should be available.
    _disable_default_general_purpose_subagent(model)
    return create_deep_agent(
        model=model,
        system_prompt=system_prompt,
        tools=[*analysis_tools],
        backend=backend,
        permissions=[FilesystemPermission(operations=["write"], paths=["/**"], mode="deny")],
        subagents=[executor],
        middleware=[
            FilesystemMiddleware(backend=backend, tools=["ls", "read_file", "glob", "grep"]),
            *build_audit_middleware(),
        ],
    )

async def invoke_audit_agent(
    target: FunctionTarget | None = None,
    project_root: str | None = None,
    container_name: str = CONTAINER_NAME,
    diagnostics_path: str | None = None,
    job_id: str | None = None,
) -> AuditAssessment:
    project_root = project_root if project_root is not None else PROJECT_ROOT
    model = create_model()
    agent = await create_audit_agent(
        model,
        target,
        project_root=project_root,
        container_name=container_name,
        diagnostics_path=diagnostics_path,
        job_id=job_id,
    )
    user_prompt = f"""
目标项目在本地的目录: { project_root }
目标项目在容器内映射的目录: /workspace
项目语言: python
调用任何工具前, 必须先确保传参符合工具的schema
项目的目录结构如下:
{ show_directory_tree(project_root) }
""".strip()

    if target is not None:
        user_prompt = f"{user_prompt}\n\n{render_function_target(target, project_root)}"

    result = await agent.ainvoke(
        {
            "blackboard_events": {},
            "blackboard_text": INITIAL_BLACKBOARD,
            "messages": [
                HumanMessage(
                    content=user_prompt
                    #content="调用executor，让它使用append_blackboard工具随便写入一条内容"
                )
            ],
        },
        config={"callbacks": tracing_callbacks(), "tags": [f"bridge-job:{job_id}"] if job_id else []},
    )
    final_message = result["messages"][-1]
    blackboard = render_blackboard_events(result.get("blackboard_events", {}))
    return await finalize_audit_result(
        model,
        str(final_message.content),
        blackboard,
        config={
            "callbacks": tracing_callbacks(),
            "tags": [f"bridge-job:{job_id}", "structured-finalization"] if job_id else ["structured-finalization"],
        },
    )


async def run_audit_agent(
    target: FunctionTarget | None = None,
    project_root: str | None = None,
    container_name: str = CONTAINER_NAME,
    output_path: str = "./out.txt",
    diagnostics_path: str | None = None,
    job_id: str | None = None,
) -> str:
    result = await invoke_audit_agent(
        target,
        project_root=project_root,
        container_name=container_name,
        diagnostics_path=diagnostics_path,
        job_id=job_id,
    )
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    serialized = serialize_audit_result(result)
    with open(output_path, "w", encoding="utf-8") as f:
        print(serialized, file=f)
    return serialized


def remove_stale_container(client: docker.DockerClient, container_name: str) -> None:
    """
    清除上一次运行残留的同名容器.

    容器只在 run() 的 finally 里清理, 进程被强杀时 (devcontainer 重启、服务被
    kill -9) 那一步不会执行. Docker 的容器名在容器退出后依然算被占用, 残留的
    容器会让后续每一次 containers.run 都以 409 Conflict 失败, 且不会自愈.

    每次运行使用独立容器名。若显式复用某个名称，清理同名的上次残留实例后再启动。
    """
    try:
        stale = client.containers.get(container_name)
    except docker.errors.NotFound:
        return

    logger.info("发现残留容器 %s (%s), 正在移除...", container_name, stale.short_id)
    try:
        stale.remove(force=True)
        logger.info("残留容器已移除. ")
    except docker.errors.APIError:
        # 不中断: 让紧随其后的 containers.run 报出名称冲突, 原始错误更贴近实际原因.
        logger.warning("残留容器移除失败, 本次创建可能因名字冲突而失败", exc_info=True)


def clear_container_checkout(container) -> bool:
    """Deletes the bind-mounted checkout contents as the container user."""
    try:
        container.reload()
        if container.status != "running":
            return False
        result = container.exec_run(
            ["find", "/workspace", "-mindepth", "1", "-delete"],
            stream=False,
            user="root",
        )
        if result.exit_code != 0:
            logger.warning("清理容器内检出目录失败: %s", result.output)
            return False
        logger.info("容器内检出目录已清理")
        return True
    except Exception:
        logger.exception("清理容器内检出目录失败")
        return False


def release_codebadger_job(job_id: str) -> None:
    """Tell CodeBadger that this audit no longer needs its loaded CPGs."""
    mcp_url = os.getenv("CodeBadger_URL")
    if not mcp_url:
        return
    parsed = urlsplit(mcp_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        logger.warning("CodeBadger_URL is not an HTTP endpoint; cannot release audit resources")
        return
    base_path = parsed.path.rstrip("/")
    if base_path.endswith("/mcp"):
        base_path = base_path[:-4]
    path = f"{base_path}/audit-jobs/{quote(job_id, safe='')}/release"
    endpoint = urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))
    request = Request(endpoint, data=b"{}", headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urlopen(request, timeout=30) as response:
            response.read()
    except Exception:
        logger.warning("Failed to release CodeBadger resources for audit %s", job_id, exc_info=True)


def run(
    target: FunctionTarget | None = None,
    *,
    project_root: str | None = None,
    container_name: str | None = None,
    output_path: str = "./out.txt",
    job_id: str | None = None,
    cancel_event: threading.Event | None = None,
    cleanup_checkout: bool = False,
) -> str:
    project_root = project_root if project_root is not None else PROJECT_ROOT
    # Every invocation owns its Docker container, even for callers that do not
    # provide an explicit name. This keeps independent audits from colliding.
    container_name = container_name or f"{CONTAINER_NAME}-{uuid.uuid4().hex[:12]}"
    lease_job_id = job_id or uuid.uuid4().hex
    diagnostics_path = str(Path(output_path).with_name(f"docker_tools_list-{container_name}.txt"))
    client = docker.from_env()
    container = None
    checkout_cleared = False

    result = ""

    try:
        logger.info("正在启动Docker容器...")
        remove_stale_container(client, container_name)
        container = client.containers.run(
            image="mcr.microsoft.com/devcontainers/anaconda:3",
            command="sleep infinity",
            detach=True,
            name=container_name,
            auto_remove=False,
            volumes={
                project_root: {
                    "bind": "/workspace",
                    "mode": "rw",
                }
            },
            working_dir="/workspace",
        )
        logger.info("启动成功!")

        async def invoke() -> str:
            nonlocal checkout_cleared
            audit = asyncio.create_task(run_audit_agent(
                target,
                project_root=project_root,
                container_name=container_name,
                output_path=output_path,
                diagnostics_path=diagnostics_path,
                job_id=lease_job_id,
            ))
            if cancel_event is None:
                return await audit
            while not audit.done():
                if cancel_event.is_set():
                    audit.cancel()
                    if cleanup_checkout:
                        checkout_cleared = clear_container_checkout(container)
                    # Tool calls may be waiting inside Docker. Stopping this
                    # run's own container releases them while the coroutine
                    # unwinds; the outer finally still removes the container.
                    try:
                        container.stop(timeout=5)
                    except Exception:
                        logger.warning("停止审计容器时出错，继续取消 Agent", exc_info=True)
                    break
                await asyncio.wait({audit}, timeout=0.2)
            return await audit

        result = asyncio.run(invoke())

    except Exception:
        # 记下完整 traceback, 然后原样抛给调用方. 只记不抛的话, 上层拿到的是空的
        # 返回值, 只能报一句泛化的"agent 没有返回结论", 真实原因 (例如容器名
        # 409 冲突) 就只剩这条日志里有了, 面板上完全看不出来.
        # finally 里的容器清理不受影响, 异常抛出前会照常执行.
        logger.exception("agent执行失败")
        raise

    finally:
        release_codebadger_job(lease_job_id)
        if container is not None:
            if cleanup_checkout and not checkout_cleared:
                checkout_cleared = clear_container_checkout(container)
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
