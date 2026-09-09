import os
from pathlib import Path
from dotenv import load_dotenv

# Base backend directory
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

# Model and Vectorizer file paths (absolute resolution prevents cwd errors)
DEFAULT_MODEL_PATH = BASE_DIR.parent / "ML Model" / "model" / "promptguard_model.pkl"
DEFAULT_VECTORIZER_PATH = BASE_DIR.parent / "ML Model" / "model" / "tfidf_vectorizer.pkl"

MODEL_PATH = Path(os.getenv("MODEL_PATH", str(DEFAULT_MODEL_PATH))).resolve()
VECTORIZER_PATH = Path(os.getenv("VECTORIZER_PATH", str(DEFAULT_VECTORIZER_PATH))).resolve()

# Security & limits
MAX_PROMPT_LENGTH = int(os.getenv("MAX_PROMPT_LENGTH", 2000))

# CORS origins
raw_origins = os.getenv(
    "CORS_ORIGINS",
    "http://localhost:3000,http://127.0.0.1:3000,http://localhost:5000,http://127.0.0.1:5000"
)
CORS_ORIGINS = [origin.strip() for origin in raw_origins.split(",") if origin.strip()]