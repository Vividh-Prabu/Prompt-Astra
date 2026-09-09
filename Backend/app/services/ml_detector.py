"""Adapter for Project Astra's pre-trained PromptGuard model."""

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import joblib


MODEL_DIR = Path(__file__).resolve().parents[2] / "ML Model" / "model"
MODEL_PATH = MODEL_DIR / "promptguard_model.pkl"
VECTORIZER_PATH = MODEL_DIR / "tfidf_vectorizer.pkl"


class ModelUnavailableError(RuntimeError):
    """Raised when the trained model artifacts cannot be used."""


@dataclass(frozen=True)
class MLAnalysis:
    ml_score: float
    predicted_category: str


@lru_cache(maxsize=1)
def _load_model_artifacts():
    """Load the trained classifier and its fitted TF-IDF vectorizer once."""
    try:
        return joblib.load(MODEL_PATH), joblib.load(VECTORIZER_PATH)
    except Exception as exc:
        raise ModelUnavailableError("PromptGuard model artifacts could not be loaded.") from exc


def _category_name(prediction: object) -> str:
    labels = {
        "0": "Safe",
        "1": "Prompt Injection",
        "2": "Jailbreak",
        "3": "Malicious",
    }
    return labels.get(str(prediction), str(prediction))


def analyze_with_model(prompt: str) -> MLAnalysis:
    """Score a prompt with the saved model using its original TF-IDF pipeline."""
    model, vectorizer = _load_model_artifacts()

    try:
        transformed_prompt = vectorizer.transform([prompt])
        prediction = model.predict(transformed_prompt)[0]
        predicted_category = _category_name(prediction)

        if hasattr(model, "predict_proba"):
            probabilities = model.predict_proba(transformed_prompt)[0]
            threat_probability = sum(
                probability
                for label, probability in zip(model.classes_, probabilities)
                if _category_name(label).lower() not in {"safe", "benign", "0"}
            )
            ml_score = float(threat_probability)
        else:
            ml_score = 0.0 if predicted_category.lower() in {"safe", "benign"} else 1.0

        return MLAnalysis(
            ml_score=max(0.0, min(1.0, ml_score)),
            predicted_category=predicted_category,
        )
    except Exception as exc:
        raise ModelUnavailableError("PromptGuard model prediction failed.") from exc
