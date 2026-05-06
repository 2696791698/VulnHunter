from langchain_openai import ChatOpenAI
from dotenv import load_dotenv
import os

load_dotenv(override=True)

def create_model() -> ChatOpenAI:
    model = ChatOpenAI(
        model=os.getenv("MODEL_NAME"),
        api_key=os.getenv("OPENAI_API_KEY"),
        base_url=os.getenv("OPENAI_BASE_URL"),
        extra_body={"thinking": {"type": "disabled"}},
        # reasoning_effort="xhigh",
        streaming=True,
        stream_usage=True,
        max_retries=3,
    )

    return model