from datasets import load_dataset
import pandas as pd
from pathlib import Path

# Load the dataset
print("Loading dataset...")
ds = load_dataset("cyberec/Prompt-injection-dataset", "core")

# Combine all splits
frames = []

for split in ["train", "validation", "test"]:
    df = ds[split].to_pandas()
    frames.append(df)

data = pd.concat(frames, ignore_index=True)

# Remove empty prompts and duplicates
data = data.dropna(subset=["text"])
data["text"] = data["text"].astype(str).str.strip()
data = data[data["text"] != ""]
data = data.drop_duplicates(subset=["text"])

# Map original categories to PromptGuard labels
def map_category(category):
    category = str(category).lower()

    if category == "benign":
        return "Safe"

    if category in {
        "jailbreak",
        "crescendo",
        "many_shot",
        "adversarial",
        "persona_replacement",
    }:
        return "Jailbreak"

    if category in {
        "direct_injection",
        "indirect_injection",
        "prompt_injection",
        "instruction_override",
        "system_manipulation",
        "token_smuggling",
        "prompt_extraction",
        "system_extraction",
        "training_extraction",
        "context_confusion",
        "model_fingerprinting",
        "multi_turn",
    }:
        return "Prompt Injection"

    if category in {
        "encoding",
        "encoding_obfuscation",
        "payload_injection",
        "code_execution",
        "rag_poisoning",
        "agent_manipulation",
        "output_manipulation",
        "response_manipulation",
        "control",
        "edge_case",
        "token_injection",
        "prompt_leak",
        "chain_of_thought",
    }:
        return "Malicious"

    # Unknown categories
    return "Malicious"


data["label"] = data["category"].apply(map_category)

# Keep only the columns needed for training
final_data = data[["text", "label", "category"]].copy()

# Rename text column to match your existing project
final_data = final_data.rename(columns={"text": "prompt"})

# Shuffle the dataset
final_data = final_data.sample(frac=1, random_state=42).reset_index(drop=True)

# Save the new dataset
output_path = Path("dataset/prompts_large.csv")
output_path.parent.mkdir(parents=True, exist_ok=True)

final_data.to_csv(output_path, index=False)

print("\nDataset prepared successfully!")
print(f"Total prompts: {len(final_data)}")

print("\nLabel distribution:")
print(final_data["label"].value_counts())

print("\nOriginal category distribution:")
print(final_data["category"].value_counts())

print(f"\nSaved to: {output_path}")