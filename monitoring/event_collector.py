"""Normalización de eventos originados en el laboratorio."""

from datetime import datetime, timezone
from ipaddress import ip_address


def failed_login_event(source_ip: str, username: str) -> dict:
    return {
        "event_type": "failed_login",
        "source_ip": str(ip_address(source_ip)),
        "target": "servidor-web",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "metadata": {"username": username, "success": False},
    }
