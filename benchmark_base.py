from pathlib import Path
import base_agent
import pandas as pd
import os

def iter_variant_paths(dataset_root: Path):
    for sample_dir in sorted(dataset_root.iterdir(), key=lambda p: p.name):
        for variant_name in ("Alpha", "Beta"):
            variant_dir = sample_dir / variant_name
            if variant_dir.is_dir():
                yield sample_dir.name, variant_name


def main():
    dataset_root = Path(__file__).resolve().parent / "dataset"
    if not dataset_root.is_dir():
        raise SystemExit(f"dataset not found: {dataset_root}")

    rows = []
    for sample_name, variant_name in iter_variant_paths(dataset_root):
        base_agent.PROJECT_ROOT = os.path.abspath(f"./dataset/{sample_name}/{variant_name}")
        result = base_agent.run()
        result = result.strip().lower()
        label = 0 if "non-vulnerable" in result else 1
        print(f"{sample_name}-{variant_name} -> label={label}")
        rows.append({
            "Project": f"{sample_name}-{variant_name}",
            "Vulnerable": label
        })

    out_df = pd.DataFrame(rows)
    out_df.to_csv("./manifest_base.csv", index=False, encoding="utf-8")
    print("saved to ./manifest_base.csv")


if __name__ == "__main__":
    main()
