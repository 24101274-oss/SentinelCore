from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.config import Settings
from backend.models import AuditEntry, Block, Incident


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def record_audit(
    session: Session,
    actor: str,
    action: str,
    source_ip: str,
    target: str,
    incident_id: str | None,
    detail: str,
) -> None:
    session.add(
        AuditEntry(
            id=str(uuid4()),
            timestamp=utc_now(),
            actor=actor,
            action=action,
            source_ip=source_ip,
            target=target,
            incident_id=incident_id,
            detail=detail[:300],
        )
    )


def expire_blocks(session: Session) -> None:
    """Marca como vencidos los bloqueos cuyo plazo terminó y lo deja en la auditoría."""
    now = utc_now()
    vencidos = session.scalars(
        select(Block).where(Block.status == "active", Block.expires_at <= now)
    ).all()
    for block in vencidos:
        block.status = "expired"
        block.released_at = block.expires_at
        record_audit(
            session, "system", "block_expired", block.source_ip, block.target,
            block.incident_id, "El bloqueo temporal venció y el acceso se restauró.",
        )


def find_active_block(session: Session, source_ip: str, target: str) -> Block | None:
    expire_blocks(session)
    return session.scalar(
        select(Block)
        .where(Block.source_ip == source_ip, Block.target == target, Block.status == "active")
        .limit(1)
    )


def create_block(
    session: Session, incident: Incident, settings: Settings, actor: str, reason: str
) -> None:
    """Crea un bloqueo temporal (si no hay uno activo) y marca el incidente como contenido."""
    if find_active_block(session, incident.source_ip, incident.target) is None:
        now = utc_now()
        session.add(
            Block(
                id=str(uuid4()),
                incident_id=incident.id,
                source_ip=incident.source_ip,
                target=incident.target,
                status="active",
                created_at=now,
                expires_at=now + settings.block_duration,
            )
        )
        segundos = int(settings.block_duration.total_seconds())
        record_audit(
            session, actor, "block_created", incident.source_ip, incident.target, incident.id,
            f"Bloqueo temporal de {segundos} s tras {incident.attempts} fallos. {reason}".strip(),
        )
    incident.status = "contained"


def apply_containment(
    session: Session, incident: Incident, settings: Settings, force: bool = False
) -> None:
    """Crea un bloqueo temporal si el incidente quedó pendiente de contención."""
    if incident.status != "pending_containment" or not settings.auto_containment:
        return  # con AUTO_CONTAINMENT=false queda pendiente para aprobación humana

    if settings.ai_enabled and not force:
        previous = session.scalar(
            select(AuditEntry.detail)
            .where(AuditEntry.incident_id == incident.id, AuditEntry.action == "ai_decision")
            .limit(1)
        )
        if previous is not None:
            # La IA ya decidió sobre este incidente: se conserva su resultado.
            active = find_active_block(session, incident.source_ip, incident.target)
            incident.status = "contained" if active else "review"
            incident.reason = f"{incident.reason} IA: {previous}"[:300]
        return  # si no, la IA decide después de guardar el evento

    create_block(session, incident, settings, "system", "")


def apply_ai_decision(session: Session, incident: Incident, decision, settings: Settings) -> None:
    """Ejecuta la decisión de la IA solo si pasa los guardarraíles."""
    detail = f"{decision.action} (confianza {decision.confidence:.2f}): {decision.explanation}"
    record_audit(
        session, "ai", "ai_decision", incident.source_ip, incident.target, incident.id, detail
    )
    incident.reason = f"{incident.reason} IA: {detail}"[:300]
    if decision.action == "block" and decision.confidence >= settings.ai_min_confidence:
        create_block(session, incident, settings, "ai", "Decisión de la IA.")
    else:
        incident.status = "review"
        incident.recommended_action = "review"