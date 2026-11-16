from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from backend.api.routes import router
from backend.config import Settings
from backend.database import open_database


def create_app(settings: Settings | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.settings = settings if settings is not None else Settings.from_environment()
        app.state.engine = open_database(app.state.settings.database_url)
        try:
            yield
        finally:
            app.state.engine.dispose()

    app = FastAPI(title="SentinelCore", version="0.1.0", lifespan=lifespan)
    app.include_router(router)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/", include_in_schema=False)
    def dashboard() -> RedirectResponse:
        return RedirectResponse("/dashboard/")

    frontend = Path(__file__).resolve().parents[1] / "frontend"
    app.mount("/dashboard", StaticFiles(directory=frontend, html=True, check_dir=False), name="dashboard")
    return app


app = create_app()
