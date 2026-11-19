"""Entrega de eventos al backend del laboratorio."""

import http.client
import json
from urllib.parse import urlencode, urlsplit
from uuid import UUID, uuid4


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
        self._request("POST", "/api/events", event, expected_status=201, idempotent=True)

    def check_access(self, source_ip: str) -> dict:
        query = urlencode({"source_ip": source_ip, "target": "servidor-web"})
        decision = self._request("GET", f"/api/blocks/check?{query}")
        if not isinstance(decision.get("blocked"), bool):
            raise EventDeliveryError("La respuesta de política no es válida")
        if decision["blocked"]:
            try:
                UUID(decision["block_id"])
            except (KeyError, TypeError, ValueError) as error:
                raise EventDeliveryError("El bloqueo recibido no tiene un identificador válido") from error
        return decision

    def observe_access(self, source_ip: str, http_status: int, block_id: str | None) -> None:
        observation = {
            "source_ip": source_ip,
            "target": "servidor-web",
            "http_status": http_status,
            "request_id": str(uuid4()),
            "block_id": block_id,
        }
        result = self._request("POST", "/api/access/observations", observation, expected_status=201)
        if result.get("recorded") is not True:
            raise EventDeliveryError("La observación de acceso no fue confirmada")

    def _request(
        self, method: str, path: str, body: dict | None = None,
        expected_status: int = 200, idempotent: bool = False,
    ) -> dict:
        payload = json.dumps(body, ensure_ascii=True) if body is not None else None
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self._token}",
        }
        if idempotent:
            headers["Idempotency-Key"] = str(uuid4())
        try:
            return self._deliver(method, path, payload, headers, expected_status)
        except (OSError, http.client.HTTPException):
            try:
                return self._deliver(method, path, payload, headers, expected_status)
            except (OSError, http.client.HTTPException) as error:
                raise EventDeliveryError("La ingesta no está disponible") from error

    def _deliver(
        self, method: str, path: str, payload: str | None,
        headers: dict[str, str], expected_status: int,
    ) -> dict:
        connection = self._connect(self._host, self._port, timeout=3)
        try:
            connection.request(method, path, body=payload, headers=headers)
            with connection.getresponse() as response:
                if response.status != expected_status:
                    raise EventDeliveryError(f"Respuesta del backend HTTP {response.status}")
                try:
                    result = json.loads(response.read(65537))
                except (UnicodeDecodeError, ValueError) as error:
                    raise EventDeliveryError("El backend devolvió una respuesta inválida") from error
                if not isinstance(result, dict):
                    raise EventDeliveryError("El backend devolvió una respuesta inválida")
                return result
        finally:
            connection.close()
