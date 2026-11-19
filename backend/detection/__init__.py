from datetime import datetime
from collections import Counter
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.config import Settings
from backend.models import Incident, SecurityEvent
from backend.containment import apply_containment, expire_blocks, find_active_block, policy_exclusion

def response_recommendation(source_ip: str, severity: str, settings: Settings) -> tuple[str, str, str]:
    if severity == "medium":
        return "alert", "review", "Se recomienda revisar la alerta."

    exclusion = policy_exclusion(source_ip, "servidor-web", settings)
    if exclusion:
        return "review", "review", exclusion
    return "pending_containment", "temporary_block", "La IP es candidata a un bloqueo temporal."


def correlate(session: Session, event: SecurityEvent, settings: Settings) -> None:
    expire_blocks(session)
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
    usernames = Counter(item.details["username"] for item in evidence)
    incident.category = (
        "possible_password_spraying"
        if count >= settings.high_threshold and len(usernames) >= 5 and max(usernames.values()) <= 2
        else "possible_brute_force"
    )
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
    active = find_active_block(session, incident.source_ip, incident.target)
    if active is not None:
        incident.status = "contained" if active.verified_at is not None else "pending_verification"
    else:
        apply_containment(session, incident, settings)
