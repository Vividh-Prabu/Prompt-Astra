from datasets import load_dataset

ds = load_dataset("cyberec/Prompt-injection-dataset", "core")

print(ds)

print("\nLabel distribution:")
print(ds["train"].to_pandas()["label"].value_counts())

print("\nCategory distribution:")
print(ds["train"].to_pandas()["category"].value_counts())