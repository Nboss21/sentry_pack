"""
FastAPI Application entrypoint. Binds 127.0.0.1 loopback interface only.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.routes import modules, projects, targets, runs, findings, sessions, reports
from api.ws import run_stream, session_stream

app = FastAPI(
    title="SentryPack API",
    description="Backend REST API and WebSocket interface for SentryPack platform",
    version="0.1.0",
)

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

app.include_router(run_stream.router)
app.include_router(session_stream.router)


@app.get("/health")
def health_check():
    return {"status": "ok", "service": "SentryPack API"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.main:app", host="127.0.0.1", port=8000, reload=True)
