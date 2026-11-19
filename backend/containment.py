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


def apply_containment(session: Session, incident: Incident, settings: Settings) -> None:
    """Crea un bloqueo temporal si el incidente quedó pendiente de contención."""
    if incident.status != "pending_containment" or not settings.auto_containment:
        return  # con AUTO_CONTAINMENT=false queda pendiente para aprobación humana

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
            session, "system", "block_created", incident.source_ip, incident.target,
            incident.id, f"Bloqueo temporal de {segundos} s tras {incident.attempts} fallos.",
        )
    incident.status = "contained"