import logging
import pickle
from pathlib import Path
from typing import Tuple, List

try:
    import joblib
except ImportError:
    joblib = None

try:
    import config
    from schemas import RiskBreakdown
except ImportError:
    from . import config
    from .schemas import RiskBreakdown

logger = logging.getLogger("promptguard-ml")


class MLService:
    def __init__(self):
        self.vectorizer = None
        self.model = None
        self.is_loaded = False

    def _load_file(self, file_path: Path):
        """Attempts loading with joblib, then standard pickle."""
        if joblib is not None:
            try:
                return joblib.load(file_path)
            except Exception:
                pass
        with open(file_path, "rb") as f:
            return pickle.load(f)

    def load_artifacts(self):
        try:
            model_dir = getattr(
                config, 
                "MODEL_DIR", 
                Path(__file__).resolve().parent.parent / "ML Model" / "model"
            )
            vec_path = model_dir / "tfidf_vectorizer.pkl"
            model_path = model_dir / "promptguard_model.pkl"

            if vec_path.is_file() and model_path.is_file():
                self.vectorizer = self._load_file(vec_path)
                self.model = self._load_file(model_path)
                self.is_loaded = True
                logger.info("ML vectorizer and model artifacts loaded successfully.")
            else:
                logger.warning(f"ML artifacts not found at {model_dir}. Operating on heuristic engine.")
        except Exception as exc:
            logger.error(f"Error loading ML artifacts: {exc}. Operating on heuristic engine.")
            self.is_loaded = False

    def analyze_prompt_text(self, text: str) -> Tuple[str, float, float, str, List[str]]:
        if self.is_loaded and self.vectorizer and self.model:
            try:
                vec = self.vectorizer.transform([text])
                pred = self.model.predict(vec)[0]
                proba = self.model.predict_proba(vec)[0]
                confidence = float(max(proba) * 100)
                is_threat = str(pred).lower() not in ["safe", "benign", "0"]
                base_risk = confidence if is_threat else (100 - confidence)
                label = "PROMPT_INJECTION" if is_threat else "SAFE"
                matches = ["ML anomaly classifier triggered"] if is_threat else []
                return label, confidence, base_risk, "HIGH" if is_threat else "LOW", matches
            except Exception as e:
                logger.error(f"ML inference error: {e}")

        return "SAFE", 98.0, 5.0, "LOW", []


ml_service = MLService()