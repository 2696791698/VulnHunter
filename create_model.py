import os
import uuid

from dotenv import load_dotenv
from langchain_openai import ChatOpenAI

load_dotenv(override=True)

# opencode zen 的 Go 网关要求带一个稳定的会话 id 用于路由，缺了会返回
# MissingSessionID。只在指向这个网关时才发，免得给别的 provider 塞无意义的头。
SESSION_HEADER = "x-opencode-session"
SESSION_GATEWAY = "opencode.ai/zen/go"


def _session_headers(base_url: str | None) -> dict[str, str]:
    if not base_url or SESSION_GATEWAY not in base_url:
        return {}
    # 每个 create_model() 调用生成一个：调用点都在一次审计的入口，
    # 所以一次审计一个会话，同一次运行内的所有请求共用同一个 id。
    return {SESSION_HEADER: str(uuid.uuid4())}


def create_model() -> ChatOpenAI:
    base_url = os.getenv("OPENAI_BASE_URL")

    model = ChatOpenAI(
        model=os.getenv("MODEL_NAME"),
        api_key=os.getenv("OPENAI_API_KEY"),
        base_url=base_url,
        extra_body={"thinking": {"type": "disabled"}},
        # reasoning_effort="xhigh",
        streaming=True,
        stream_usage=True,
        max_retries=3,
        default_headers=_session_headers(base_url),
    )

    return model
