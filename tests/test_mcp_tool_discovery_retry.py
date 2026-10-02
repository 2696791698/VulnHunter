from types import SimpleNamespace
from unittest.mock import patch

import pytest

import audit_agent


class McpError(Exception):
    pass


class _Tool:
    def __init__(self, name: str):
        self.name = name


@pytest.mark.asyncio
async def test_analysis_tool_discovery_retries_transient_server_disconnect(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    calls: dict[str, int] = {}

    class ClientStub:
        def __init__(self, connections, **kwargs):
            self.connections = connections

        async def get_tools(self, *, server_name=None):
            calls[server_name] = calls.get(server_name, 0) + 1
            if server_name == "Semgrep" and calls[server_name] == 1:
                raise McpError("Connection closed")
            return [_Tool(f"{server_name}_safe_tool")]

    with patch.object(audit_agent, "MultiServerMCPClient", ClientStub):
        tools = await audit_agent.get_analysis_tools("audit-retry")

    assert calls == {"CodeBadger": 1, "CodeQL": 1, "Semgrep": 2}
    assert {tool.name for tool in tools} == {
        "CodeBadger_safe_tool", "CodeQL_safe_tool", "Semgrep_safe_tool"
    }


@pytest.mark.asyncio
async def test_analysis_tool_discovery_fails_closed_on_permanent_server_error(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    calls: dict[str, int] = {}

    class ClientStub:
        def __init__(self, connections, **kwargs):
            self.connections = connections

        async def get_tools(self, *, server_name=None):
            calls[server_name] = calls.get(server_name, 0) + 1
            if server_name == "CodeQL":
                raise ValueError("invalid server configuration")
            return [_Tool(f"{server_name}_safe_tool")]

    with patch.object(audit_agent, "MultiServerMCPClient", ClientStub):
        with pytest.raises(RuntimeError, match="CodeQL"):
            await audit_agent.get_analysis_tools("audit-failed-init")

    assert calls["CodeQL"] == 1


@pytest.mark.asyncio
async def test_runtime_retry_is_limited_to_read_only_codebadger_tools():
    request = SimpleNamespace(server_name="CodeBadger", name="list_calls")
    attempts = 0

    async def handler(_request):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise McpError("Connection closed")
        return "query result"

    assert await audit_agent._retry_codebadger_read_tool_call(request, handler) == "query result"
    assert attempts == 2

    request.name = "generate_cpg"
    attempts = 0

    async def failing_handler(_request):
        nonlocal attempts
        attempts += 1
        raise McpError("Connection closed")

    with pytest.raises(McpError):
        await audit_agent._retry_codebadger_read_tool_call(request, failing_handler)
    assert attempts == 1
