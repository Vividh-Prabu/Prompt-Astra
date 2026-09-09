import os
import pandas as pd
from datasets import load_dataset

# ============================================================
# 1. Load your previous dataset
# ============================================================

PREVIOUS_FILE = "dataset/prompts_large.csv"

if not os.path.exists(PREVIOUS_FILE):
    raise FileNotFoundError(
        f"Could not find {PREVIOUS_FILE}. "
        "Put your previous CSV inside the dataset folder."
    )

old_df = pd.read_csv(PREVIOUS_FILE)

print("Previous dataset:", old_df.shape)
print("Previous columns:", old_df.columns.tolist())


# ============================================================
# 2. Load the S-Labs dataset
# ============================================================

print("\nLoading S-Labs dataset...")

ds = load_dataset("S-Labs/prompt-injection-dataset")

# Combine train, validation, and test
s_labs_df = pd.concat(
    [
        ds["train"].to_pandas(),
        ds["validation"].to_pandas(),
        ds["test"].to_pandas()
    ],
    ignore_index=True
)

print("S-Labs dataset:", s_labs_df.shape)
print("S-Labs columns:", s_labs_df.columns.tolist())


# ============================================================
# 3. Convert previous dataset into binary labels
# ============================================================

old_df = old_df.rename(columns={
    "prompt": "text"
})

old_df = old_df[["text", "label"]].copy()

# Remove empty prompts
old_df = old_df.dropna(subset=["text", "label"])

old_df["text"] = old_df["text"].astype(str).str.strip()

old_df = old_df[old_df["text"] != ""]

# Convert all previous labels into binary labels
old_df["label"] = old_df["label"].astype(str).str.strip()

old_df["label"] = old_df["label"].apply(
    lambda x: 0 if x.lower() == "safe" else 1
)


# ============================================================
# 4. Prepare S-Labs dataset
# ============================================================

s_labs_df = s_labs_df[["text", "label"]].copy()

s_labs_df = s_labs_df.dropna(subset=["text", "label"])

s_labs_df["text"] = s_labs_df["text"].astype(str).str.strip()

s_labs_df = s_labs_df[s_labs_df["text"] != ""]

s_labs_df["label"] = s_labs_df["label"].astype(int)


# ============================================================
# 5. Merge both datasets
# ============================================================

merged_df = pd.concat(
    [old_df, s_labs_df],
    ignore_index=True
)

print("\nBefore removing duplicates:", merged_df.shape)


# ============================================================
# 6. Remove duplicate prompts
# ============================================================

merged_df = merged_df.drop_duplicates(
    subset=["text"],
    keep="first"
)

merged_df = merged_df.sample(
    frac=1,
    random_state=42
).reset_index(drop=True)

print("After removing duplicates:", merged_df.shape)


# ============================================================
# 7. Display label distribution
# ============================================================

print("\nFinal label distribution:")
print(merged_df["label"].value_counts())

print("\nFinal dataset preview:")
print(merged_df.head())


# ============================================================
# 8. Save the merged dataset
# ============================================================

os.makedirs("dataset", exist_ok=True)

OUTPUT_FILE = "dataset/merged_promptguard_dataset.csv"

merged_df.to_csv(
    OUTPUT_FILE,
    index=False
)

print(f"\n✅ Merged dataset saved to: {OUTPUT_FILE}")