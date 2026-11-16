"""Entrega de eventos al backend del laboratorio."""

import http.client
import json
from urllib.parse import urlsplit
from uuid import uuid4


class EventDeliveryError(Exception):
    """El backend no confirmó la ingesta del evento."""


class EventAgent:
    def __init__(self, backend_url: str, token: str):
        url = urlsplit(backend_url)
        if (
            url.scheme not in {"http", "https"}
            or not url.hostname
            or url.username is not None
            or url.path not in {"", "/"}
            or url.query
            or url.fragment
        ):
            raise ValueError("BACKEND_URL debe indicar solo el origen HTTP del backend")

        self._host = url.hostname
        self._port = url.port
        self._connect = (
            http.client.HTTPSConnection if url.scheme == "https" else http.client.HTTPConnection
        )
        self._token = token

    def send(self, event: dict) -> None:
        payload = json.dumps(event, ensure_ascii=True)
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self._token}",
            "Idempotency-Key": str(uuid4()),
        }
        try:
            self._deliver(payload, headers)
        except (OSError, http.client.HTTPException):
            try:
                self._deliver(payload, headers)
            except (OSError, http.client.HTTPException) as error:
                raise EventDeliveryError("La ingesta no está disponible") from error

    def _deliver(self, payload: str, headers: dict[str, str]) -> None:
        connection = self._connect(self._host, self._port, timeout=3)
        try:
            connection.request("POST", "/api/events", body=payload, headers=headers)
            with connection.getresponse() as response:
                if response.status != 201:
                    raise EventDeliveryError(f"Respuesta de ingesta HTTP {response.status}")
        finally:
            connection.close()
