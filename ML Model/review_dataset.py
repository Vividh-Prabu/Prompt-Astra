import pandas as pd

FILE = "dataset/prompts_large.csv"

df = pd.read_csv(FILE)

# Terms that deserve manual review.
# These are NOT automatically considered incorrect.
review_terms = [
    "ignore previous",
    "bypass",
    "jailbreak",
    "hacked",
    "pwned",
    "system prompt",
    "reveal instructions",
    "steal",
    "password",
    "credit card",
    "malware",
    "keylogger",
    "hate speech",
    "insider trading",
    "exfiltrate",
    "rm -rf",
    "os.system",
    "shell command",
]

pattern = "|".join(review_terms)

review_df = df[
    df["prompt"].astype(str).str.contains(
        pattern,
        case=False,
        na=False,
        regex=True
    )
].copy()

review_df.to_csv(
    "dataset/prompts_needing_review.csv",
    index=False
)

print("Total dataset:", len(df))
print("Rows needing review:", len(review_df))
print("Saved to: dataset/prompts_needing_review.csv")

print("\nLabel distribution of review rows:")
print(review_df["label"].value_counts())

print("\nFirst 20 rows:")
print(review_df.head(20).to_string(index=False))