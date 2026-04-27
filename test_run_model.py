import asyncio
import os
from dotenv import load_dotenv
from deepagents import create_deep_agent
from deepagents.backends import LocalShellBackend
from langchain_openai import ChatOpenAI
from langchain_mcp_adapters.client import MultiServerMCPClient
from langsmith import traceable
from rich.console import Console
from rich.pretty import pprint
from langchain.tools import tool
from tree_utils import show_tree
import docker
import logging

load_dotenv()

PROJECT_ROOT = "/home/houning/Projects/dataset/qwq"

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

async def main():
    model = ChatOpenAI(
        model="deepseek-v4-pro",
        api_key=os.getenv("DeepSeek_API_KEY"),
        base_url=os.getenv("DeepSeek_BASE_URL"),
        reasoning_effort="max",
        extra_body={"thinking": {"type": "enabled"}},
        streaming=True,
        stream_usage=True,
        max_retries=3,
    )

    client = MultiServerMCPClient(
        {
            # "CodeBadger": {
            #     "transport": "http",
            #     "url": "http://127.0.0.1:4242/mcp",
            # },
            # "CodeQL": {
            #     "transport": "stdio",
            #     "command": "codeql-development-mcp-server-schema-fixed",
            #     "args": [],
            # },
            # "Semgrep": {
            #     "transport": "stdio",
            #     "command": "semgrep",
            #     "args": ["mcp"],
            #     "env": {
            #         **os.environ,
            #         "PS1": "$ ",
            #         "USE_SEMGREP_RPC": "false",
            #     },
            # },
            "docker-mcp": {
                "transport": "sse",
                "url": "http://127.0.0.1:19000/sse",
            },
        }
    )

    mcp_tools = await client.get_tools()

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

    mcp_tools = [tool for tool in mcp_tools if tool.name not in blocked_tools]

    with open(f"./mcp_tools_list.txt", "w", encoding="utf-8") as f:
        console = Console(file=f)
        pprint(mcp_tools, console=console)

    system_prompt = """
""".strip()

    user_prompt = """
你现在的任务是在 anaconda-container 的环境中, 检查能否正常运行目标项目
目标项目在本地的目录: /home/houning/Projects/dataset/qwq
目标项目在容器内映射的目录: /workspace
语言: python
请先调用 show_directory_tree 工具快速了解目标项目的目录结构
""".strip()

    # 声明 Subagents
    executor = {
        "name": "executor",
        "description": "据上层提供的漏洞假设或验证计划，在受控环境中对目标项目进行动态验证，判断漏洞是否能够被实际触发，并返回验证证据、复现步骤或失败原因。",
        "system_prompt": """
你是一名专业的漏洞动态验证代理，负责执行验证，而不是制定整体审计策略。

你的任务是：根据输入中的漏洞假设、攻击思路或验证计划，对目标项目进行最小必要的动态验证，判断漏洞是否真实存在以及是否可以被触发。

行为要求：
1. 严格依据提供的漏洞假设或计划执行，不自行扩展新的攻击方向。
2. 只进行与当前验证目标直接相关的最小化操作，避免无关探索。
3. 每一步操作都应能够支持或反驳漏洞存在。
4. 如果验证成功，必须提供清晰、可复现的最小 PoC 或复现步骤。
5. 如果验证失败，需说明失败原因（如条件不足、路径不可达、输入受限等），而不是直接否定漏洞。
6. 不要编造执行结果；无法确认时应明确说明不确定性。
7. 输出应简洁且结构化，重点突出结论与证据。

请按如下结构输出：
- Status: confirmed / unconfirmed / inconclusive
- Steps:
- Evidence:
- PoC:
- Failure Reason:
"""
    }

    subagents = [executor] 

    agent = create_deep_agent(
        model=model,
        tools=[show_directory_tree, *mcp_tools],
        # system_prompt=system_prompt,
        backend=LocalShellBackend(root_dir=PROJECT_ROOT, virtual_mode=False),
        # subagents=subagents
    )

    result = await agent.ainvoke({
        "messages": [
            {"role": "user", "content": "你好"}
        ]
    })

    print(result["messages"][-1].content)

if __name__ == "__main__":
    client = docker.from_env()
    container = None

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

        asyncio.run(main())

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
