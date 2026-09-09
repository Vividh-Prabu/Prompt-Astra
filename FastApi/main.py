import logging
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

# Guarantee FastApi directory is root in path
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from supabase import Client, create_client

import config
from ml_service import ml_service
from schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    BatchAnalyzeRequest,
    BatchAnalyzeResponse,
    HealthResponse,
)
from services.prediction_service import (
    analyze_batch_prompts,
    analyze_single_prompt,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("promptguard-api")

possible_envs = [
    BASE_DIR / ".env",
    BASE_DIR.parent / ".env",
    BASE_DIR.parent / "Backend" / ".env",
]

for env_path in possible_envs:
    if env_path.is_file():
        load_dotenv(env_path)
        logger.info(f"Loaded environment variables from: {env_path}")
        break

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = (
    os.getenv("SUPABASE_SERVICE_ROLE_KEY")
    or os.getenv("SUPABASE_KEY")
    or os.getenv("SUPABASE_ANON_KEY")
)

supabase: Optional[Client] = None
if SUPABASE_URL and SUPABASE_KEY:
    try:
        supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
        logger.info("Supabase client initialized successfully.")
    except Exception as exc:
        logger.error(f"Failed to initialize Supabase: {exc}")
else:
    logger.warning("Supabase credentials not found. Database logging disabled.")


def log_event_to_supabase(prompt_text: str, result: AnalyzeResponse):
    """Persists events into security_events table."""
    if not supabase:
        return
    try:
        data = {
            "prompt": prompt_text.strip(),
            "decision": str(result.decision).upper(),
            "risk_score": int(result.risk_score),
            "threat_category": str(result.label).upper().replace(" ", "_"),
            "ml_score": float(
                getattr(result.breakdown, "ml_confidence_score", 0.0) or 0.0
            ),
            "rule_score": float(
                getattr(result.breakdown, "instruction_override_risk", 0.0) or 0.0
            ),
        }
        supabase.table("security_events").insert(data).execute()
        logger.info(f"Successfully recorded event [{result.decision}] to Supabase.")
    except Exception as exc:
        logger.error(f"Supabase logging error: {exc}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    if hasattr(ml_service, "load_artifacts"):
        ml_service.load_artifacts()
    yield


app = FastAPI(
    title="Prompt Astra Enterprise Security API",
    description="Advanced AI Firewall & Guardrail Engine.",
    version="2.0.0",
    lifespan=lifespan,
)

cors_origins = getattr(config, "CORS_ORIGINS", ["*"])

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", summary="Root Endpoint")
async def root():
    return {
        "service": "Prompt Astra AI Guardrail",
        "status": "online",
        "supabase_connected": supabase is not None,
        "docs": "/docs",
    }


@app.get("/health", response_model=HealthResponse, summary="Health Check")
async def health():
    return HealthResponse(
        status="operational",
        model_loaded=getattr(ml_service, "is_loaded", True),
        version="2.0.0",
    )


@app.post("/analyze", response_model=AnalyzeResponse, summary="Deep Prompt Scan")
async def analyze(payload: AnalyzeRequest, background_tasks: BackgroundTasks):
    try:
        result = analyze_single_prompt(payload)
    except Exception as exc:
        logger.exception("ML analysis failed")
        raise HTTPException(status_code=500, detail="ML analysis failed.") from exc

    # Only log to Supabase / Threat Monitor if explicitly confirmed
    if supabase and payload.store_event:
        background_tasks.add_task(log_event_to_supabase, payload.prompt, result)

    return result

@app.post(
    "/analyze/batch",
    response_model=BatchAnalyzeResponse,
    summary="Batch Prompt Scan",
)
async def analyze_batch(payload: BatchAnalyzeRequest):
    try:
        return analyze_batch_prompts(payload)
    except Exception as exc:
        logger.exception("Batch execution error")
        raise HTTPException(status_code=500, detail="Batch execution failed.") from exc


@app.get("/analyze/stream", summary="Live Keystroke Scanner (SSE)")
async def stream_analyze(
    prompt: str = Query(
        ..., max_length=getattr(config, "MAX_PROMPT_LENGTH", 4096)
    )
):
    async def event_generator():
        req = AnalyzeRequest(prompt=prompt, sanitize=True)
        res = analyze_single_prompt(req)
        json_data = (
            res.model_dump_json()
            if hasattr(res, "model_dump_json")
            else res.json()
        )
        yield f"data: {json_data}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")