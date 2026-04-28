import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

sns.set_theme(style="dark")
sns.set_context("paper")

def calc_metrics(csv_path):
    df = pd.read_csv(csv_path)

    tp = tn = fp = fn = 0

    for vul_id, vulnerable in zip(df["vul_id"], df["Vulnerable"]):
        if "Alpha" in vul_id and vulnerable == 1:
            tp += 1
        elif "Beta" in vul_id and vulnerable == 0:
            tn += 1
        elif "Beta" in vul_id and vulnerable == 1:
            fp += 1
        elif "Alpha" in vul_id and vulnerable == 0:
            fn += 1

    # 整体判对了多少
    accuracy = (tp + tn) / (tp + tn + fp + fn)

    # 模型判有漏洞时，有多少次真有漏洞
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0

    # 有漏洞里，模型抓出来多少
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0

    # Precision 和 Recall 的调和平均
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    return accuracy, precision, recall, f1

tools_metrics = calc_metrics("/home/houning/Projects/agent/result_tools.csv")
no_tools_metrics = calc_metrics("/home/houning/Projects/agent/result_no_tools.csv")

labels = ["Accuracy", "Precision", "Recall", "F1"]
tools_values = list(tools_metrics)
no_tools_values = list(no_tools_metrics)

x = range(len(labels))
width = 0.3

plt.figure(figsize=(10,6), dpi=200)

palette = sns.color_palette("pastel")

bars1 = plt.bar(
    [i - width / 2 for i in x],
    tools_values,
    width=width,
    label="GPT-5.4 (low) - Tools",
    color=palette[0]
)

bars2 = plt.bar(
    [i + width / 2 for i in x],
    no_tools_values,
    width=width,
    label="GPT-5.4 (low) - No Tools",
    color=palette[1]
)

plt.xticks(list(x), labels)
plt.ylim(0, 1.15)
plt.title("Performance of models on Vul4J (N = 10)")
plt.legend()

for bar in bars1:
    h = bar.get_height()
    plt.text(
        bar.get_x() + bar.get_width() / 2,
        h,
        f"{h:.3f}",
        ha="center",
        va="bottom"
    )

for bar in bars2:
    h = bar.get_height()
    plt.text(
        bar.get_x() + bar.get_width() / 2, h,
        f"{h:.3f}",
        ha="center",
        va="bottom"
    )

plt.tight_layout()
plt.savefig("compare.png")