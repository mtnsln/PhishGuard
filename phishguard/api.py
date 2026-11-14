from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import __version__
from .analyzer import analyze_url

BASE_DIR = Path(__file__).resolve().parent.parent
app = FastAPI(
    title="PhishGuard API",
    description="Explainable, offline-first URL risk analysis. Submitted URLs are never fetched.",
    version=__version__,
)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


class AnalyzeRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048, description="URL text to analyse")


@app.get("/", include_in_schema=False)
def home():
    return FileResponse(BASE_DIR / "static" / "index.html")


@app.get("/health")
def health():
    return {"status": "ok", "service": "PhishGuard", "version": __version__}


@app.post("/api/analyze")
def analyze(request: AnalyzeRequest):
    try:
        return analyze_url(request.url)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
