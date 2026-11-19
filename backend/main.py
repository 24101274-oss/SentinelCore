from contextlib import asynccontextmanager
import asyncio
import logging
from pathlib import Path
from threading import Event

from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from backend.api.routes import router
from backend.analyst import drain_pending
from backend.config import Settings
from backend.database import open_database


async def recover_pending(engine, settings: Settings, stop: Event) -> None:
    while not stop.is_set():
        try:
            await asyncio.to_thread(drain_pending, engine, settings, stop)
        except Exception as error:
            logging.getLogger("uvicorn.error").error(
                "Falló la recuperación de pendientes (%s)", type(error).__name__
            )
        await asyncio.to_thread(stop.wait, 5)


def create_app(settings: Settings | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.settings = settings if settings is not None else Settings.from_environment()
        app.state.engine = open_database(app.state.settings.database_url)
        stop = Event()
        worker = (
            asyncio.create_task(recover_pending(app.state.engine, app.state.settings, stop))
            if app.state.settings.auto_containment else None
        )
        try:
            yield
        finally:
            stop.set()
            if worker is not None:
                await worker
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
