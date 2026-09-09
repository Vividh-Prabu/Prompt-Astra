import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay
)
import matplotlib.pyplot as plt


# 1. Load the dataset
data = pd.read_csv("dataset/prompts.csv")

data = data.dropna(subset=["text", "label"])
data["text"] = data["text"].str.strip()

X = data["text"]
y = data["label"]


# 2. Split the dataset
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.4,
    random_state=42,
    stratify=y
)


# 3. Load the saved model and vectorizer
model = joblib.load("model/promptguard_model.pkl")
vectorizer = joblib.load("model/tfidf_vectorizer.pkl")


# 4. Convert test prompts into TF-IDF features
X_test_tfidf = vectorizer.transform(X_test)


# 5. Make predictions
y_pred = model.predict(X_test_tfidf)


# 6. Calculate evaluation metrics
accuracy = accuracy_score(y_test, y_pred)

print("========== MODEL EVALUATION ==========")
print("Accuracy:", round(accuracy * 100, 2), "%")

print("\nClassification Report:")
print(classification_report(y_test, y_pred, zero_division=0))


# 7. Display confusion matrix
cm = confusion_matrix(y_test, y_pred, labels=model.classes_)

print("\nConfusion Matrix:")
print(cm)

disp = ConfusionMatrixDisplay(
    confusion_matrix=cm,
    display_labels=model.classes_
)

disp.plot(xticks_rotation=45)
plt.tight_layout()
plt.show()