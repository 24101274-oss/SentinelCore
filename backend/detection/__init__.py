from datetime import datetime
from ipaddress import ip_address
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.config import Settings
from backend.models import Incident, SecurityEvent


def response_recommendation(source_ip: str, severity: str, settings: Settings) -> tuple[str, str, str]:
    if severity == "medium":
        return "alert", "review", "Se recomienda revisar la alerta."

    address = ip_address(source_ip)
    protected = address.is_loopback or address.is_unspecified or address.is_multicast or address.is_link_local
    if protected or any(address in network for network in settings.allowlist):
        return "review", "review", "La IP está exceptuada por la política."
    if not any(address in network for network in settings.lab_networks):
        return "review", "review", "La IP está fuera de las redes autorizadas del laboratorio."
    return "pending_containment", "temporary_block", "La IP es candidata a un bloqueo temporal."


def correlate(session: Session, event: SecurityEvent, settings: Settings) -> None:
    scope = (SecurityEvent.source_ip == event.source_ip, SecurityEvent.target == event.target)
    latest = session.scalar(
        select(SecurityEvent.timestamp)
        .where(*scope)
        .order_by(SecurityEvent.timestamp.desc())
        .limit(1)
    )
    cutoff = latest - min(settings.window, latest - datetime.min)
    if event.timestamp < cutoff:
        return

    evidence = session.scalars(
        select(SecurityEvent)
        .where(*scope, SecurityEvent.timestamp >= cutoff)
        .order_by(SecurityEvent.timestamp, SecurityEvent.id)
    ).all()
    count = len(evidence)
    if count < settings.medium_threshold:
        return
    event.severity = "high" if count >= settings.high_threshold else "medium"

    incident = session.scalar(
        select(Incident)
        .where(
            Incident.source_ip == event.source_ip,
            Incident.target == event.target,
            Incident.last_seen >= cutoff,
        )
        .order_by(Incident.last_seen.desc(), Incident.id)
        .limit(1)
    )
    if incident is None:
        incident = Incident(
            id=str(uuid4()),
            source_ip=event.source_ip,
            target=event.target,
            first_seen=evidence[0].timestamp,
            event_count=0,
            attempts=count,
            severity=event.severity,
        )
        session.add(incident)

    incident.last_seen = latest
    incident.attempts = max(incident.attempts, count)
    if event.severity == "high":
        incident.severity = "high"
    incident.status, incident.recommended_action, explanation = response_recommendation(
        event.source_ip, incident.severity, settings
    )
    incident.reason = (
        f"Pico de {incident.attempts} fallos en una ventana de "
        f"{settings.window.total_seconds():g} s. {explanation}"
    )
    newly_linked = [item for item in evidence if item.incident_id is None]
    incident.first_seen = min(incident.first_seen, evidence[0].timestamp)
    incident.event_count += len(newly_linked)
    session.flush()
    for item in newly_linked:
        item.incident_id = incident.id
    event.receipt_incident_id = incident.id
