import pandas as pd

FILE = "dataset/prompts_large.csv"

df = pd.read_csv(FILE)

print("Total rows:", len(df))
print("\nColumns:")
print(df.columns.tolist())

print("\nLabel distribution:")
print(df["label"].value_counts())

print("\nCategory distribution:")
print(df["category"].value_counts())

print("\nSample prompts:")
for i, row in df.head(10).iterrows():
    print(f"\n{i + 1}. {row['prompt']}")
    print(f"   Label: {row['label']}")
    print(f"   Category: {row['category']}")