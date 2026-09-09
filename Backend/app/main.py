from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routes import analyze
from app.routes import logs
from app.routes import stats

app = FastAPI(title="Prompt Astra API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register the API routes
app.include_router(analyze.router, prefix="/api", tags=["Analysis"])
app.include_router(logs.router, prefix="/api", tags=["Logs"])
app.include_router(stats.router, prefix="/api", tags=["Stats"])


@app.get("/")
def root():
    return {"message": "Prompt Astra API is running"}


@app.get("/health")
def health():
    return {"status": "healthy"}