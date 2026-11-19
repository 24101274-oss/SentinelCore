from datetime import datetime, timezone
from ipaddress import IPv6Address, ip_address
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.config import Settings
from backend.models import AuditEntry, Block, Incident


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def record_audit(
    session: Session, actor: str, action: str, source_ip: str, target: str,
    incident_id: str | None, detail: str,
) -> None:
    session.add(AuditEntry(
        id=str(uuid4()), timestamp=utc_now(), actor=actor, action=action,
        source_ip=source_ip, target=target, incident_id=incident_id, detail=detail[:300],
    ))


def policy_exclusion(source_ip: str, target: str, settings: Settings) -> str | None:
    address = ip_address(source_ip)
    if isinstance(address, IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if target != "servidor-web":
        return "El destino está fuera del laboratorio autorizado."
    if address.is_loopback or address.is_unspecified or address.is_multicast or address.is_link_local:
        return "La IP está exceptuada por la política."
    if any(address in network for network in settings.allowlist):
        return "La IP está en ALLOWLIST."
    if not any(address in network for network in settings.lab_networks):
        return "La IP está fuera de LAB_CIDRS."
    return None


def mark_restoration_pending(session: Session, block: Block) -> None:
    incident = session.get(Incident, block.incident_id)
    if incident is not None:
        incident.status = "restoration_pending"
        incident.ai_started_at = None


def expire_blocks(session: Session) -> None:
    now = utc_now()
    expired = session.scalars(
        select(Block).where(Block.status == "active", Block.expires_at <= now)
    ).all()
    for block in expired:
        block.status = "expired"
        block.released_at = block.expires_at
        mark_restoration_pending(session, block)
        record_audit(
            session, "system", "block_expired", block.source_ip, block.target,
            block.incident_id, "Venció el bloqueo. La restauración requiere un acceso permitido.",
        )
    session.flush()


def find_active_block(session: Session, source_ip: str, target: str) -> Block | None:
    return session.scalar(
        select(Block).where(
            Block.source_ip == source_ip, Block.target == target,
            Block.status == "active", Block.expires_at > utc_now(),
        ).order_by(Block.created_at.desc()).limit(1)
    )


def release_containment(session: Session, block: Block, actor: str = "admin") -> None:
    block.status = "released"
    block.released_at = utc_now()
    mark_restoration_pending(session, block)
    record_audit(
        session, actor, "block_released", block.source_ip, block.target, block.incident_id,
        "Bloqueo liberado. La restauración requiere un acceso permitido.",
    )


def create_block(
    session: Session, incident: Incident, settings: Settings, actor: str, reason: str,
) -> Block | None:
    """Registrar una restricción pendiente de evidencia del servicio protegido."""
    exclusion = policy_exclusion(incident.source_ip, incident.target, settings)
    if exclusion or incident.severity != "high":
        incident.status = "review"
        incident.recommended_action = "review"
        incident.reason = exclusion or "La severidad requiere revisión."
        return None

    expire_blocks(session)
    active = find_active_block(session, incident.source_ip, incident.target)
    if active is not None:
        incident.status = "contained" if active.verified_at is not None else "pending_verification"
        return active
    active_count = session.scalar(
        select(func.count()).select_from(Block).where(Block.status == "active")
    )
    if active_count >= settings.max_active_blocks:
        incident.status = "review"
        incident.reason = f"Se alcanzó el límite de {settings.max_active_blocks} bloqueos activos."
        record_audit(
            session, actor, "block_limit_reached", incident.source_ip, incident.target,
            incident.id, incident.reason,
        )
        return None

    now = utc_now()
    block = Block(
        id=str(uuid4()), incident_id=incident.id, source_ip=incident.source_ip,
        target=incident.target, status="active", created_at=now,
        expires_at=now + settings.block_duration,
    )
    session.add(block)
    incident.status = "pending_verification"
    incident.ai_started_at = None
    seconds = int(settings.block_duration.total_seconds())
    record_audit(
        session, actor, "block_created", incident.source_ip, incident.target, incident.id,
        f"Restricción temporal de {seconds} s tras {incident.attempts} fallos. "
        f"Pendiente de verificar un rechazo HTTP 403. {reason}".strip(),
    )
    session.flush()
    return block


def apply_containment(
    session: Session, incident: Incident, settings: Settings, force: bool = False,
) -> None:
    if incident.status != "pending_containment" or not settings.auto_containment:
        return
    if settings.ai_enabled and not force:
        return
    create_block(session, incident, settings, "system", "Regla de umbral alto.")


def apply_ai_decision(session: Session, incident: Incident, decision, settings: Settings) -> None:
    detail = f"{decision.action} (confianza {decision.confidence:.2f}): {decision.explanation}"
    record_audit(
        session, "ai", "ai_decision", incident.source_ip, incident.target, incident.id, detail
    )
    incident.ai_started_at = None
    incident.reason = f"{incident.reason} IA: {detail}"[:300]
    if not settings.auto_containment:
        incident.status = "pending_containment"
    elif decision.action == "block" and decision.confidence >= settings.ai_min_confidence:
        create_block(session, incident, settings, "ai", "Decisión de la IA.")
    else:
        incident.status = "review"
        incident.recommended_action = "review"
