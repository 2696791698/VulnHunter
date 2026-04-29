import os
import asyncio
from dotenv import load_dotenv
from deepagents import create_deep_agent
from langchain_openai import ChatOpenAI
from langchain_mcp_adapters.client import MultiServerMCPClient

load_dotenv(override=True)


async def check_codebadger():
    try:
        client = MultiServerMCPClient(
            {
                "CodeBadger": {
                    "transport": "http",
                    "url": os.getenv("CodeBadger_URL"),
                },
            }
        )
        await client.get_tools()
        print("✅ Successfully connected to CodeBadger server!")
        return True

    except Exception as e:
        print(f"❌ Error connecting to CodeBadger server: {e}")
        return False


async def check_codeql():
    try:
        client = MultiServerMCPClient(
            {
                "CodeQL": {
                    "transport": "stdio",
                    "command": "codeql-development-mcp-server-schema-fixed",
                    "args": [],
                },
            }
        )
        await client.get_tools()
        print("✅ Successfully connected to CodeQL server!")
        return True

    except Exception as e:
        print(f"❌ Error connecting to CodeQL server: {e}")
        return False


async def check_semgrep():
    try:
        client = MultiServerMCPClient(
            {
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
        await client.get_tools()
        print("✅ Successfully connected to Semgrep server!")
        return True

    except Exception as e:
        print(f"❌ Error connecting to Semgrep server: {e}")
        return False


async def check_docker_mcp():
    try:
        client = MultiServerMCPClient(
            {
                "docker-mcp": {
                    "transport": "sse",
                    "url": os.getenv("Docker_MCP_URL"),
                },
            }
        )
        await client.get_tools()
        print("✅ Successfully connected to docker-mcp server!")
        return True

    except Exception as e:
        print(f"❌ Error connecting to docker-mcp server: {e}")
        return False


async def check_model():
    try:
        model = ChatOpenAI(
            model=os.getenv("MODEL_NAME"),
            api_key=os.getenv("OPENAI_API_KEY"),
            base_url=os.getenv("OPENAI_BASE_URL"),
        )

        agent = create_deep_agent(model=model)

        result = await agent.ainvoke(
            {
                "messages": [
                    {"role": "user", "content": "你好"}
                ]
            }
        )

        print("✅ Successfully connected to Model!")
        print(f"Model Response: {result['messages'][-1].content}")
        return True

    except Exception as e:
        print(f"❌ Error connecting to Model: {e}")
        return False


async def check_environment():
    results = {
        "CodeBadger": await check_codebadger(),
        "CodeQL": await check_codeql(),
        "Semgrep": await check_semgrep(),
        "docker-mcp": await check_docker_mcp(),
        "Model": await check_model(),
    }

    print("\n========== Environment Check Summary ==========")
    for name, ok in results.items():
        status = "✅ PASS" if ok else "❌ FAIL"
        print(f"{name}: {status}")


if __name__ == "__main__":
    asyncio.run(check_environment())