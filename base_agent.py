import asyncio
from dotenv import load_dotenv
from deepagents import create_deep_agent
from deepagents.backends import FilesystemBackend
from create_model import create_model
from audit_result import finalize_audit_result, serialize_audit_result

load_dotenv(override=True)

PROJECT_ROOT = ""

async def main():
    model = create_model()

    system_prompt = """
你是一名专业的代码安全审计员.

任务目标:
- 对给定项目目录中的代码进行静态安全审计
- 最终判断当前检测项目是否存在安全漏洞
- 只有实际攻击成功且观察到安全影响, 才判定存在漏洞; 如果最终无法成功攻击, 本次审计判定为无漏洞

行为约束:
- 不允许把猜测写成已确认事实
- 只允许读取目标项目中的文件, 不允许访问目标项目之外的任何路径
- 不允许修改、创建、删除、重命名任何文件或目录
- 只在有明确结论时才结束审计, 证据不足时继续调查
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

    return await finalize_audit_result(model, str(result["messages"][-1].content))

def run():
    assessment = asyncio.run(main())
    return serialize_audit_result(assessment)

if __name__ == "__main__":
    run()
