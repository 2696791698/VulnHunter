import os
from dotenv import load_dotenv
from deepagents import create_deep_agent
from deepagents.backends import LocalShellBackend
from langchain_openai import ChatOpenAI
from langchain_mcp_adapters.client import MultiServerMCPClient

load_dotenv()

async def run_sample(path: str):
    model = ChatOpenAI(
        model="gpt-5.4",
        api_key=os.getenv("OPENAI_API_KEY"),
        base_url=os.getenv("OPENAI_BASE_URL"),
        reasoning_effort="low",
        streaming=True,
        stream_usage=True,
        max_retries=3
    )

    client = MultiServerMCPClient(
        {
            "CodeBadger": {
                "transport": "http",
                "url": "http://127.0.0.1:4242/mcp"
            }
        }
    )

    mcp_tools = await client.get_tools()

    system_prompt = """
你是一名专业的静态代码安全审计员

任务目标：
- 对给定审计目录中的代码进行静态安全审计
- 判断该审计目录中是否存在安全漏洞
- 你的最终目标是输出唯一的审计结论标签

行为约束：
- 优先调用代码审计工具进行辅助
- 只允许读取审计目录中的文件和子目录
- 不允许修改、创建、删除、重命名任何文件或目录
- 不允许执行任何具有写操作、副作用或破坏性的命令
- 不允许访问审计目录之外的任何路径
- 不允许编造未读取到的代码内容
- 必须基于实际读取到的代码内容作出判断

最终输出规则：
- 最终只能输出以下两个标签之一：vulnerable 或 non-vulnerable
- 必须且只能输出一个标签
- 不允许输出任何其他内容，包括但不限于：解释、分析过程、标点、空格、换行、前后缀、代码块
- 如果确认存在安全漏洞，输出：vulnerable
- 如果确认不存在安全漏洞，输出：non-vulnerable
- 除上述两个标签外，禁止输出其它任何内容
""".strip()

    agent = create_deep_agent(
        model=model,
        tools=[*mcp_tools],
        system_prompt=system_prompt,
        backend=LocalShellBackend(root_dir=".", virtual_mode=False)
    )

    prompt = f"""
审计目录：{path}
""".strip()

    result = await agent.ainvoke({
        "messages": [
            {"role": "user", "content": prompt}
        ]
    })

    return result