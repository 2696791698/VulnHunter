import pandas as pd

df = pd.read_csv("/home/houning/Projects/agent/result_tools.csv")

tp = 0
tn = 0
fp = 0
fn = 0

for vul_id, vulnerable in zip(df["vul_id"], df["Vulnerable"]):
    if ("Alpha" in vul_id and vulnerable == 1):
        tp = tp + 1
    elif ("Beta" in vul_id and vulnerable == 0):
        tn = tn + 1
    elif ("Beta" in vul_id and vulnerable == 1):
        fp = fp + 1
    elif ("Alpha" in vul_id and vulnerable == 0):
        fn = fn + 1

# 整体判对了多少
accuracy = (tp + tn) / (tp + tn + fp + fn)

# 模型判有漏洞时，有多少次真有漏洞
precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0

# 有漏洞里，模型抓出来多少
recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0

# Precision 和 Recall 的调和平均
f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

print(accuracy, precision, recall, f1, sep=" | ")