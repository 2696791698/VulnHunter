import asyncio
import os
from dotenv import load_dotenv
from deepagents import create_deep_agent
from deepagents.backends import FilesystemBackend
from langchain_openai import ChatOpenAI

load_dotenv()

PROJECT_ROOT = "./dataset/CWE-79_0020_plone_plone.namedfile_GHSA-jj7c-jrv4-c65x/Alpha"

async def main():
    model = ChatOpenAI(
        model=os.getenv("MODEL_NAME"),
        api_key=os.getenv("OPENAI_API_KEY"),
        base_url=os.getenv("OPENAI_BASE_URL"),
        reasoning_effort="low",
        streaming=True,
        stream_usage=True,
        max_retries=3,
    )

    system_prompt = """
你是一名专业的代码安全审计员.

任务目标:
- 对给定项目目录中的代码进行静态安全审计
- 最终判断当前检测项目是否存在安全漏洞

行为约束:
- 不允许把猜测写成已确认事实
- 只允许读取目标项目中的文件, 不允许访问目标项目之外的任何路径
- 不允许修改、创建、删除、重命名任何文件或目录
- 只在有明确结论时才结束审计, 不要在不确定时结束审计

最终输出规则:
- 如果判断存在漏洞, 请严格输出 vulnerable
- 如果判断不存在漏洞, 请严格输出 non-vulnerable
- 只允许输出以上两种指标, 不要输出 uncertain 或 inconclusive 等模糊结论
""".strip()

    user_prompt = f"""
目标项目在本地的目录: { PROJECT_ROOT }
语言: python
""".strip()

    agent = create_deep_agent(
        model=model,
        system_prompt=system_prompt,
        backend=FilesystemBackend(root_dir=PROJECT_ROOT, virtual_mode=False),
    )

    result = await agent.ainvoke({
        "messages": [
            {"role": "user", "content": user_prompt}
        ]
    })

    return(result["messages"][-1].content)

def run():
    result = asyncio.run(main())
    return result

if __name__ == "__main__":
    run()