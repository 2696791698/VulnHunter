from __future__ import annotations
import asyncio
import json
import os
from dataclasses import dataclass, field
from dotenv import load_dotenv
from collections.abc import Callable
from typing import Annotated, Any, Literal
from deepagents import create_deep_agent
from deepagents.backends import LocalShellBackend
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
from pydantic import BaseModel, Field, ConfigDict

load_dotenv()

INITIAL_BLACKBOARD = """- 初始化: 尚无已确认事实
"""


class AuditState(AgentState):
    """
    审计状态（append-only blackboard）. 

    blackboard_text:
        黑板全文，只允许在末尾追加新条目. 
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
[Blackboard]
以下是 append-only blackboard（仅允许追加，不允许覆盖历史）：
- 仅 executor 可写，主 agent 与其他角色不可写. 
- 仅将 blackboard 已写入条目视为已确认事实. 
- 若证据已足够支持结论，请直接收敛. 

{blackboard_text.strip() or INITIAL_BLACKBOARD}
""".strip()


class EvidenceRef(BaseModel):
    kind: Literal["file", "command", "output", "url", "other"] = Field(
        description="证据类型. "
    )
    ref: str = Field(min_length=1, description="证据引用，例如文件路径、命令、输出ID或URL. ")
    quote: str | None = Field(default=None, description="可选，证据关键片段. ")


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
        raise ValueError("runtime.tool_call_id 为空，无法构造匹配的 ToolMessage. ")

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
    # 只给主 agent 注入，executor 调用不注入. 
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


def build_model() -> ChatOpenAI:
    return ChatOpenAI(
        model="gpt-5.4",
        api_key=os.getenv("OPENAI_API_KEY"),
        base_url=os.getenv("OPENAI_BASE_URL"),
        reasoning_effort="low",
        streaming=True,
        stream_usage=True,
        max_retries=3,
    )


def build_deep_audit_agent(model: ChatOpenAI):
    executor = {
        "name": "executor",
        "description": "执行最小必要动态验证，并通过 append_blackboard 工具追加已确认事实到黑板. ",
        "system_prompt": """
你是一名专业的漏洞动态验证代理，负责执行，不负责制定整体审计策略. 

你的任务：
- 严格依据上层给出的验证目标执行
- 只进行与当前漏洞假设直接相关的最小必要操作
- 给出可复现步骤与关键证据
- 不要把“未复现”写成“漏洞不存在”

你是 blackboard 的唯一写入者，且只允许“追加写”. 不得改写历史条目. 
当你拿到“已确认事实/已排除假设/当前结论”后，必须调用 append_blackboard 工具写入. 
调用要求：
- facts 传本轮已确认事实列表（至少 1 条，且每条必须以 '- ' 开头）
- evidence 传证据数组（kind, ref, quote）
不要通过普通文本回包写 blackboard. 

输出结构（保留）：
- Status: confirmed / unconfirmed / inconclusive
- Steps:
- Evidence:
- PoC:
- Failure Reason:
""".strip(),
        "tools": [append_blackboard],
    }

    system_prompt = """
    你是一名专业的静态代码安全审计员. 

    任务目标：
    - 对给定审计目录中的代码进行静态安全审计
    - 在需要时调用 executor 做最小必要动态验证
    - 始终依据 blackboard（append-only）中的已确认事实收敛
    - 最终判断当前检测项目是否存在安全漏洞

    行为约束：
    - 你没有 blackboard 写权限，禁止尝试写入或改写 blackboard
    - blackboard 只能由 executor 调用 append_blackboard 工具追加
    - 优先依据实际读取到的代码、工具返回结果、executor 返回结果判断
    - 不允许把猜测写成已确认事实
    - 只允许读取审计目录中的文件和子目录
    - 不允许修改、创建、删除、重命名任何文件或目录
    - 不允许执行具有写操作、副作用或破坏性的命令
    - 不允许访问审计目录之外的任何路径
    - 如果 blackboard 已经明确支持最终结论，应立即结束探索

    最终输出规则：
    - 给出你的审计结论
    - 如有请说明你在审计过程中遇到的问题, 帮助我修复agent环境
    """.strip()

# """
# 最终输出规则：
#     - 最终只能输出以下两个标签之一：vulnerable 或 non-vulnerable
#     - 必须且只能输出一个标签
#     - 不允许输出任何其他内容
# """

    return create_deep_agent(
        model=model,
        system_prompt=system_prompt,
        backend=LocalShellBackend(root_dir="/home/houning/Projects/dataset/VUL4J-16/Beta", virtual_mode=True),
        subagents=[executor],
        middleware=build_blackboard_middleware(),
    )

async def audit_current_project() -> dict[str, Any]:
    BLACKBOARD_STORE.reset(INITIAL_BLACKBOARD)
    model = build_model()
    agent = build_deep_audit_agent(model)
    return await agent.ainvoke(
        {
            "blackboard_text": INITIAL_BLACKBOARD,
            "messages": [
                HumanMessage(
                    content="请审计当前路径的项目代码，必要时调用 executor 做动态验证"
                )
            ],
        }
    )


async def main() -> None:
    result = await audit_current_project()
    # print(result["messages"][-1].content)


if __name__ == "__main__":
    asyncio.run(main())
