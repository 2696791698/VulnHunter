"""Check that thinking-mode tool turns retain provider reasoning_content."""

import os
import sys
from pathlib import Path
from unittest.mock import patch

from langchain_core.messages import AIMessageChunk, ToolMessage, message_chunk_to_message

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from create_model import ReasoningContentChatOpenAI, create_model  # noqa: E402


def main() -> None:
    with patch.dict(
        os.environ,
        {
            "MODEL_NAME": "deepseek-v4.1-flash",
            "MODEL_REASONING_EFFORT": "max",
            "OPENAI_API_KEY": "test-only",
            "OPENAI_BASE_URL": "https://example.invalid/v1",
        },
    ):
        model = create_model()

    assert isinstance(model, ReasoningContentChatOpenAI)
    chunks = [
        {"choices": [{"delta": {"role": "assistant", "reasoning_content": "first "}}]},
        {"choices": [{"delta": {"reasoning_content": "thought"}}]},
    ]
    generations = [
        model._convert_chunk_to_generation_chunk(chunk, AIMessageChunk, None)
        for chunk in chunks
    ]
    assert all(generation is not None for generation in generations)
    message = message_chunk_to_message((generations[0] + generations[1]).message)
    message.tool_calls = [{"name": "lookup", "args": {}, "id": "call_test"}]

    payload = model._get_request_payload(
        [message, ToolMessage(content="ok", tool_call_id="call_test")],
        tools=[
            {
                "type": "function",
                "function": {
                    "name": "lookup",
                    "parameters": {"type": "object", "properties": {}},
                },
            }
        ],
    )
    assert payload["messages"][0]["reasoning_content"] == "first thought"
    assert payload["messages"][0]["tool_calls"][0]["id"] == "call_test"
    assert payload["messages"][1]["tool_call_id"] == "call_test"
    print("PASS: streamed reasoning_content survives a tool-call continuation")


if __name__ == "__main__":
    main()
