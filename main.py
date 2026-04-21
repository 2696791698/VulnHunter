import asyncio
import os
from dotenv import load_dotenv
from deepagents import create_deep_agent
from deepagents.backends import LocalShellBackend
from langchain_openai import ChatOpenAI
from langchain_mcp_adapters.client import MultiServerMCPClient
from langsmith import traceable

load_dotenv()

async def agent():
    model = ChatOpenAI(
        model="gpt-5.4",
        api_key=os.getenv("OPENAI_API_KEY"),
        base_url=os.getenv("OPENAI_BASE_URL"),
        reasoning_effort="low",
        streaming=True,
        stream_usage=True,
        max_retries=3
    )

    # client = MultiServerMCPClient(
    #     {
    #         "CodeBadger": {
    #             "transport": "http",
    #             "url": "http://127.0.0.1:4242/mcp"
    #         }
    #     }
    # )

    # mcp_tools = await client.get_tools()

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

    prompt = f"""
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
        # tools=[*mcp_tools],
        # system_prompt=system_prompt,
        backend=LocalShellBackend(root_dir=".", virtual_mode=False),
        subagents=subagents
    )

    result = await agent.ainvoke({
        "messages": [
            {"role": "user", "content": "你好, 列出你当前的环境和所有工具还有subagent"}
        ]
    })

    print(result)

if __name__ == "__main__":
    asyncio.run(agent())