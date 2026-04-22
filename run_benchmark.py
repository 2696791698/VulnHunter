import asyncio
import pandas as pd
from run_one_sample import run_sample
from rich.console import Console
from rich.pretty import pprint

df = pd.read_csv("/home/houning/Projects/dataset/manifest.csv")

async def main():
    rows = []

    for vul_id in df["vul_id"][75:85]:
        for variant in ["Alpha", "Beta"]:
            path = f"/home/houning/Projects/dataset/{vul_id}/{variant}"
            result = await run_sample(path)
            with open(f"./out/tools/{vul_id}_{variant}.txt", "w", encoding="utf-8") as f:
                print(result["messages"][-1].content, file=f)
                print("-" * 100, file=f)
                console = Console(file=f)
                pprint(result, console=console)

            content = result["messages"][-1].content
            text = content.lower().strip()

            label = 0 if "non-vulnerable" in text  else 1

            rows.append({
                "vul_id": f"{vul_id}-{variant}",
                "Vulnerable": label
            })

            print(f"{vul_id}-{variant} -> model_output={text} label={label}")

    out_df = pd.DataFrame(rows)
    out_df.to_csv("./result_tools.csv", index=False, encoding="utf-8")
    print("saved to ./result_tools.csv")

asyncio.run(main())