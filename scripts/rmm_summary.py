import pandas as pd
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
FINDINGS_FILE = BASE_DIR / "findings.csv"
SUMMARY_FILE = BASE_DIR / "tool_summary.csv"

df = pd.read_csv(FINDINGS_FILE)

summary = (
    df.groupby("tool")
    .size()
    .reset_index(name="count")
    .sort_values("count", ascending=False)
)

summary.to_csv(SUMMARY_FILE, index=False)

print(summary)
print(f"\nSaved summary to {SUMMARY_FILE}")
