"""
FastAPI Application entrypoint. Binds 127.0.0.1 loopback interface only.
"""

from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from api.routes import modules, projects, targets, runs, findings, sessions, reports, exploits, transports
from api.ws import run_stream, session_stream
from core.run_store import run_store as _run_store  # noqa: F401
from core.transport_registry import transport_registry
from api.db.session import init_db

TRANSPORTS_DIR = Path(__file__).resolve().parent.parent / "modules" / "transports"
C2_TRANSPORTS_DIR = Path(__file__).resolve().parent.parent / "modules" / "c2" / "transports"

app = FastAPI(
    title="SentryPack API",
    description="Backend REST API and WebSocket interface for SentryPack platform",
    version="0.1.0",
)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={
            "error": "validation_error",
            "message": "Request validation failed",
            "detail": jsonable_encoder(exc.errors()),
        },
    )


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    if isinstance(exc.detail, dict):
        return JSONResponse(
            status_code=exc.status_code,
            content=exc.detail,
            headers=getattr(exc, "headers", None),
        )
    error_code = "not_found" if exc.status_code == 404 else ("conflict" if exc.status_code == 409 else "http_error")
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": error_code,
            "message": str(exc.detail) if exc.detail else "Resource not found",
            "detail": exc.detail,
        },
        headers=getattr(exc, "headers", None),
    )


@app.on_event("startup")
def startup():
    init_db()
    transport_registry.scan_many([TRANSPORTS_DIR, C2_TRANSPORTS_DIR])


app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1", "http://localhost"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(modules.router, prefix="/api/modules", tags=["modules"])
app.include_router(projects.router, prefix="/api/projects", tags=["projects"])
app.include_router(targets.router, prefix="/api/targets", tags=["targets"])
app.include_router(runs.router, prefix="/api", tags=["runs"])
app.include_router(findings.router, prefix="/api", tags=["findings"])
app.include_router(sessions.router, prefix="/api/sessions", tags=["sessions"])
app.include_router(reports.router, prefix="/api/projects", tags=["reports"])
app.include_router(exploits.router, prefix="/api/exploits", tags=["exploits"])
app.include_router(transports.router, prefix="/api/transports", tags=["transports"])

app.include_router(run_stream.router)
app.include_router(session_stream.router)


@app.get("/health")
def health_check():
    return {"status": "ok", "service": "SentryPack API"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.main:app", host="127.0.0.1", port=8000, reload=True)
