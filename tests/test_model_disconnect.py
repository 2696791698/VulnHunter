"""A gateway disconnect must not lose an otherwise retryable model turn."""

import json
import os
from unittest.mock import patch

import httpx
import pytest

import create_model


class BrokenBody(httpx.AsyncByteStream):
    def __init__(self, streaming: bool):
        self.streaming = streaming

    async def __aiter__(self):
        if self.streaming:
            yield (
                b'data: {"id":"partial","object":"chat.completion.chunk",'
                b'"choices":[{"index":0,"delta":{"content":"partial"}}]}\n\n'
            )
        else:
            yield b'{"id":"partial","choices":[{"message":'
        raise httpx.RemoteProtocolError(
            "peer closed connection without sending complete message body "
            "(incomplete chunked read)"
        )


@pytest.mark.asyncio
async def test_gateway_disconnect_during_response_is_retried():
    requests = []

    def handle(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        requests.append(payload)
        if len(requests) == 1:
            streaming = payload.get("stream") is True
            return httpx.Response(
                200,
                headers={
                    "content-type": "text/event-stream" if streaming else "application/json"
                },
                stream=BrokenBody(streaming),
            )
        return httpx.Response(
            200,
            json={
                "id": "completion",
                "object": "chat.completion",
                "model": "deepseek-v4.1-flash",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "ok",
                        "reasoning_content": "checked",
                    },
                    "finish_reason": "stop",
                }],
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
        model_class = create_model.ReasoningContentChatOpenAI

        def with_test_transport(**kwargs):
            return model_class(http_async_client=client, **kwargs)

        with patch.dict(os.environ, {
            "MODEL_NAME": "deepseek-v4.1-flash",
            "MODEL_REASONING_EFFORT": "max",
            "OPENAI_API_KEY": "test-only",
            "OPENAI_BASE_URL": "https://opencode.ai/zen/go/v1",
        }), patch.object(create_model, "ReasoningContentChatOpenAI", with_test_transport):
            model = create_model.create_model()
            result = await model.ainvoke("hi")

    assert result.content == "ok"
    assert result.additional_kwargs["reasoning_content"] == "checked"
    assert len(requests) == 2
    assert all(request.get("stream") is not True for request in requests)
