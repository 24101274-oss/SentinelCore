"""Servicio protegido de prueba de SentinelCore."""

import hmac
import logging
import os
from contextlib import asynccontextmanager
from hashlib import sha256

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

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


@app.exception_handler(RequestValidationError)
async def invalid_request(_request: Request, _error: RequestValidationError):
    return JSONResponse(status_code=422, content={"detail": "Datos de inicio de sesión inválidos"})


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/login")
def login(body: LoginRequest, request: Request):
    settings = request.app.state
    valid_username = hmac.compare_digest(body.username.encode("utf-8"), settings.username)
    submitted_digest = sha256(body.password.get_secret_value().encode("utf-8")).digest()
    valid_password = hmac.compare_digest(submitted_digest, settings.password_digest)
    if valid_username and valid_password:
        return {"status": "authenticated"}

    try:
        source_ip = request.client.host if request.client else ""
        event = failed_login_event(source_ip, body.username)
        settings.events.send(event)
    except (ValueError, EventDeliveryError):
        logger.warning("El laboratorio no pudo registrar el intento fallido")
        raise HTTPException(status_code=503, detail="Ingesta de eventos no disponible") from None

    raise HTTPException(status_code=401, detail="Credenciales inválidas")


if __name__ == "__main__":
    uvicorn.run(
        app,
        host=os.getenv("HOST", "127.0.0.1"),
        port=int(os.getenv("PORT", "8001")),
        proxy_headers=False,
    )
