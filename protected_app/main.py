"""Servicio protegido de prueba de SentinelCore."""

import hmac
import logging
import os
from contextlib import asynccontextmanager
from hashlib import sha256
from ipaddress import ip_address
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator
from starlette.concurrency import run_in_threadpool

from monitoring.agent import EventAgent, EventDeliveryError
from monitoring.event_collector import failed_login_event


logger = logging.getLogger("uvicorn.error")


@asynccontextmanager
async def lifespan(app: FastAPI):
    username = os.getenv("LAB_USERNAME", "admin")
    password = os.getenv("LAB_PASSWORD")
    token = os.getenv("INGEST_TOKEN")
    if not password or not token:
        raise RuntimeError("Configura LAB_PASSWORD e INGEST_TOKEN para iniciar el laboratorio")
    if not 1 <= len(username) <= 128 or len(password) > 256:
        raise RuntimeError("LAB_USERNAME o LAB_PASSWORD superan los límites de /login")

    app.state.username = username.encode("utf-8")
    app.state.password_digest = sha256(password.encode("utf-8")).digest()
    app.state.events = EventAgent(os.getenv("BACKEND_URL", "http://127.0.0.1:8000"), token)
    yield


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=128)
    password: SecretStr = Field(max_length=256)

    @field_validator("password")
    @classmethod
    def validate_password_encoding(cls, password: SecretStr) -> SecretStr:
        try:
            password.get_secret_value().encode("utf-8")
        except UnicodeEncodeError as error:
            raise ValueError("La contraseña debe ser Unicode válido") from error
        return password


app = FastAPI(title="Laboratorio protegido de SentinelCore", lifespan=lifespan)


@app.middleware("http")
async def enforce_access(request: Request, call_next):
    if request.url.path not in {"/access", "/login"}:
        return await call_next(request)

    try:
        source_ip = str(ip_address(request.client.host if request.client else ""))
        request.state.source_ip = source_ip
        agent = request.app.state.events
        decision = await run_in_threadpool(agent.check_access, source_ip)
        if decision["blocked"]:
            await run_in_threadpool(agent.observe_access, source_ip, 403, decision["block_id"])
            return JSONResponse(status_code=403, content={
                "detail": "Acceso bloqueado temporalmente por SentinelCore",
                "status": "blocked", "source_ip": source_ip, "target": "servidor-web",
                "expires_at": decision.get("expires_at"),
            })

        response = await call_next(request)
        if request.url.path == "/access" and response.status_code == 200:
            await run_in_threadpool(agent.observe_access, source_ip, 200, None)
        return response
    except (ValueError, EventDeliveryError):
        logger.warning("El laboratorio no pudo confirmar la política o registrar el acceso")
        return JSONResponse(status_code=503, content={
            "detail": "Servicio de protección no disponible. Reintenta cuando se restablezca.",
            "status": "unavailable",
        })


@app.exception_handler(RequestValidationError)
async def invalid_request(_request: Request, _error: RequestValidationError):
    return JSONResponse(status_code=422, content={"detail": "Datos de inicio de sesión inválidos"})


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/access")
def access(request: Request):
    return {"status": "accessible", "source_ip": request.state.source_ip, "target": "servidor-web"}


@app.post("/login")
def login(body: LoginRequest, request: Request):
    settings = request.app.state
    valid_username = hmac.compare_digest(body.username.encode("utf-8"), settings.username)
    submitted_digest = sha256(body.password.get_secret_value().encode("utf-8")).digest()
    valid_password = hmac.compare_digest(submitted_digest, settings.password_digest)
    if valid_username and valid_password:
        return {"status": "authenticated"}

    try:
        source_ip = request.state.source_ip
        event = failed_login_event(source_ip, body.username)
        settings.events.send(event)
    except (ValueError, EventDeliveryError):
        logger.warning("El laboratorio no pudo registrar el intento fallido")
        raise HTTPException(status_code=503, detail="Ingesta de eventos no disponible") from None

    raise HTTPException(status_code=401, detail="Credenciales inválidas")


app.mount("/", StaticFiles(directory=Path(__file__).parent / "web", html=True), name="laboratorio")


if __name__ == "__main__":
    uvicorn.run(
        app,
        host=os.getenv("HOST", "127.0.0.1"),
        port=int(os.getenv("PORT", "8001")),
        proxy_headers=False,
    )
