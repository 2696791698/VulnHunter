import os
import re
import uuid

from dotenv import load_dotenv
from langchain_core.messages import AIMessage, AIMessageChunk
from langchain_openai import ChatOpenAI

load_dotenv(override=True)

# opencode zen 的 Go 网关要求带一个稳定的会话 id 用于路由，缺了会返回
# MissingSessionID。只在指向这个网关时才发，免得给别的 provider 塞无意义的头。
SESSION_HEADER = "x-opencode-session"
SESSION_GATEWAY = "opencode.ai/zen/go"
MIMO_REASONING_MODELS = re.compile(r"^mimo-v2\.(?:5|6)(?:-|$)", re.IGNORECASE)


def _session_headers(base_url: str | None) -> dict[str, str]:
    if not base_url or SESSION_GATEWAY not in base_url:
        return {}
    # 每个 create_model() 调用生成一个：调用点都在一次审计的入口，
    # 所以一次审计一个会话，同一次运行内的所有请求共用同一个 id。
    return {SESSION_HEADER: str(uuid.uuid4())}


class ReasoningContentChatOpenAI(ChatOpenAI):
    """Keep provider reasoning_content across Agent tool-call turns."""

    def _convert_chunk_to_generation_chunk(self, chunk, default_chunk_class, base_generation_info):
        generation = super()._convert_chunk_to_generation_chunk(
            chunk, default_chunk_class, base_generation_info
        )
        choices = chunk.get("choices") or chunk.get("chunk", {}).get("choices") or []
        if generation and choices and isinstance(generation.message, AIMessageChunk):
            reasoning = (choices[0].get("delta") or {}).get("reasoning_content")
            if reasoning is not None:
                generation.message.additional_kwargs["reasoning_content"] = reasoning
        return generation

    def _create_chat_result(self, response, generation_info=None):
        result = super()._create_chat_result(response, generation_info)
        data = response if isinstance(response, dict) else response.model_dump()
        for generation, choice in zip(result.generations, data.get("choices") or []):
            reasoning = (choice.get("message") or {}).get("reasoning_content")
            if reasoning is not None and isinstance(generation.message, AIMessage):
                generation.message.additional_kwargs["reasoning_content"] = reasoning
        return result

    def _get_request_payload(self, input_, *, stop=None, **kwargs):
        payload = super()._get_request_payload(input_, stop=stop, **kwargs)
        if "messages" in payload:
            messages = self._convert_input(input_).to_messages()
            for message, encoded in zip(messages, payload["messages"], strict=True):
                if isinstance(message, AIMessage):
                    reasoning = message.additional_kwargs.get("reasoning_content")
                    if reasoning is not None:
                        encoded["reasoning_content"] = reasoning
        return payload


def create_model() -> ChatOpenAI:
    base_url = os.getenv("OPENAI_BASE_URL") or None
    model_name = os.getenv("MODEL_NAME") or ""
    reasoning_effort = os.getenv("MODEL_REASONING_EFFORT", "none").strip() or "none"

    is_mimo = bool(MIMO_REASONING_MODELS.match(model_name))
    if is_mimo:
        thinking_type = "disabled" if reasoning_effort == "none" else "enabled"
        model_options = {
            "extra_body": {"thinking": {"type": thinking_type}},
            "use_responses_api": False,
        }
    else:
        model_options = {"reasoning_effort": reasoning_effort}

    model = ReasoningContentChatOpenAI(
        model=model_name,
        api_key=os.getenv("OPENAI_API_KEY"),
        base_url=base_url,
        **model_options,
        # The Zen Go gateway can close an SSE body mid-stream. The OpenAI
        # client's retries cover response-body reads only for non-stream calls.
        streaming=SESSION_GATEWAY not in (base_url or ""),
        stream_usage=True,
        max_retries=3,
        default_headers=_session_headers(base_url),
    )

    return model
