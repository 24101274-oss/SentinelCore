from datetime import UTC, datetime
from secrets import compare_digest
from typing import Annotated, Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Query, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, field_validator
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from backend.api.schemas import (
    EventEvidence,
    EventPayload,
    EventReceipt,
    IncidentDetail,
    IncidentPage,
    IncidentStatus,
    IncidentSummary,
    Metrics,
    Severity,
)
from backend.containment import (
    create_block, expire_blocks, find_active_block, record_audit,
    release_containment, utc_now,
)
from backend.analyst import run_analyst
from backend.detection import correlate
from backend.models import AccessObservation, AuditEntry, Block, Incident, SecurityEvent

router = APIRouter(prefix="/api")
bearer = HTTPBearer(auto_error=False)
Credentials = Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)]


def require_token(credentials: HTTPAuthorizationCredentials | None, token: str) -> None:
    if credentials is None or not compare_digest(credentials.credentials.encode(), token.encode()):
        raise HTTPException(
            status_code=401,
            detail="Credenciales requeridas o inválidas",
            headers={"WWW-Authenticate": "Bearer"},
        )


def require_ingest_token(request: Request, credentials: Credentials) -> None:
    require_token(credentials, request.app.state.settings.ingest_token)


def require_admin_token(request: Request, credentials: Credentials) -> None:
    require_token(credentials, request.app.state.settings.admin_token)


def get_session(request: Request):
    with Session(request.app.state.engine) as session:
        yield session


DatabaseSession = Annotated[Session, Depends(get_session)]


def serialize_incident(incident: Incident) -> IncidentSummary:
    return IncidentSummary(
        id=incident.id,
        category=incident.category,
        source_ip=incident.source_ip,
        target=incident.target,
        severity=incident.severity,
        status=incident.status,
        first_seen=incident.first_seen.replace(tzinfo=UTC),
        last_seen=incident.last_seen.replace(tzinfo=UTC),
        event_count=incident.event_count,
        attempts=incident.attempts,
        recommended_action=incident.recommended_action,
        reason=incident.reason,
    )


def serialize_event(event: SecurityEvent) -> EventEvidence:
    return EventEvidence(
        id=event.id,
        event_type=event.event_type,
        source_ip=event.source_ip,
        target=event.target,
        timestamp=event.timestamp.replace(tzinfo=UTC),
        metadata=event.details,
        severity=event.severity,
    )


@router.post("/events", status_code=201, dependencies=[Depends(require_ingest_token)])
def ingest_event(
    payload: EventPayload,
    request: Request,
    session: DatabaseSession,
    background: BackgroundTasks,
    idempotency_key: Annotated[UUID | None, Header()] = None,
) -> EventReceipt:
    event_id = str(idempotency_key or uuid4())
    fields = {
        "event_type": payload.event_type,
        "source_ip": payload.source_ip,
        "target": payload.target,
        "timestamp": payload.timestamp.replace(tzinfo=None),
        "details": payload.metadata.model_dump(),
    }
    # Reservar escritura antes de leer evita que dos ingestas creen el mismo incidente.
    session.execute(text("BEGIN IMMEDIATE"))
    event = session.get(SecurityEvent, event_id)
    if event is None:
        event = SecurityEvent(id=event_id, severity="low", **fields)
        session.add(event)
        correlate(session, event, request.app.state.settings)
    elif any(getattr(event, field) != value for field, value in fields.items()):
        raise HTTPException(status_code=409, detail="Esta clave de idempotencia corresponde a otro evento")

    receipt = EventReceipt(
        event_id=event.id,
        severity=event.severity,
        incident_id=event.receipt_incident_id,
    )
    session.commit()
    settings = request.app.state.settings
    if settings.ai_enabled and settings.auto_containment and receipt.incident_id:
        background.add_task(run_analyst, request.app.state.engine, receipt.incident_id, settings)
    return receipt


@router.get("/incidents", dependencies=[Depends(require_admin_token)])
def list_incidents(
    session: DatabaseSession,
    limit: Annotated[int, Query(ge=1, le=100)] = 30,
    offset: Annotated[int, Query(ge=0)] = 0,
    severity: Severity | None = None,
    status: IncidentStatus | None = None,
) -> IncidentPage:
    expire_due_blocks(session)
    filters = []
    if severity is not None:
        filters.append(Incident.severity == severity)
    if status is not None:
        filters.append(Incident.status == status)

    total = session.scalar(select(func.count()).select_from(Incident).where(*filters))
    incidents = session.scalars(
        select(Incident)
        .where(*filters)
        .order_by(Incident.last_seen.desc(), Incident.id)
        .limit(limit)
        .offset(offset)
    )
    return IncidentPage(items=[serialize_incident(incident) for incident in incidents], total=total)


@router.get("/incidents/{incident_id}", dependencies=[Depends(require_admin_token)])
def get_incident(incident_id: UUID, session: DatabaseSession) -> IncidentDetail:
    expire_due_blocks(session)
    incident = session.get(Incident, str(incident_id))
    if incident is None:
        raise HTTPException(status_code=404, detail="Incidente no encontrado")

    evidence = session.scalars(
        select(SecurityEvent)
        .where(SecurityEvent.incident_id == incident.id)
        .order_by(SecurityEvent.timestamp, SecurityEvent.id)
    )
    return IncidentDetail(
        **serialize_incident(incident).model_dump(),
        events=[serialize_event(event) for event in evidence],
    )


class BlockStatus(BaseModel):
    blocked: bool
    block_id: UUID | None = None
    expires_at: datetime | None = None


class BlockItem(BaseModel):
    id: str
    incident_id: str
    source_ip: str
    target: str
    status: str
    created_at: datetime
    expires_at: datetime
    released_at: datetime | None = None
    verified_at: datetime | None = None
    restored_at: datetime | None = None


class ObservationPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_ip: str
    target: Literal["servidor-web"]
    http_status: Literal[200, 403]
    request_id: UUID
    block_id: UUID | None = None

    @field_validator("source_ip")
    @classmethod
    def normalize_ip(cls, value: str) -> str:
        return EventPayload.normalize_ip(value)


class AuditItem(BaseModel):
    id: str
    timestamp: datetime
    actor: str
    action: str
    source_ip: str
    target: str
    incident_id: str | None = None
    detail: str


def serialize_block(block: Block) -> BlockItem:
    return BlockItem(
        id=block.id, incident_id=block.incident_id, source_ip=block.source_ip,
        target=block.target, status=block.status,
        created_at=block.created_at.replace(tzinfo=UTC),
        expires_at=block.expires_at.replace(tzinfo=UTC),
        released_at=block.released_at.replace(tzinfo=UTC) if block.released_at else None,
        verified_at=block.verified_at.replace(tzinfo=UTC) if block.verified_at else None,
        restored_at=block.restored_at.replace(tzinfo=UTC) if block.restored_at else None,
    )


def expire_due_blocks(session: Session) -> None:
    """Las consultas frecuentes solo escriben cuando hay un vencimiento pendiente."""
    due = session.scalar(
        select(Block.id).where(Block.status == "active", Block.expires_at <= utc_now()).limit(1)
    )
    if due is not None:
        session.rollback()
        session.execute(text("BEGIN IMMEDIATE"))
        expire_blocks(session)
        session.commit()


@router.get("/access/check", dependencies=[Depends(require_ingest_token)])
@router.get("/blocks/check", dependencies=[Depends(require_ingest_token)])
def check_block(source_ip: str, target: Literal["servidor-web"], session: DatabaseSession) -> BlockStatus:
    try:
        source_ip = EventPayload.normalize_ip(source_ip)
    except ValueError as error:
        raise HTTPException(status_code=422, detail="source_ip inválida") from error
    expire_due_blocks(session)
    block = find_active_block(session, source_ip, target)
    if block is None:
        return BlockStatus(blocked=False)
    return BlockStatus(
        blocked=True, block_id=block.id, expires_at=block.expires_at.replace(tzinfo=UTC)
    )


@router.post("/access/observations", status_code=201, dependencies=[Depends(require_ingest_token)])
def observe_access(payload: ObservationPayload, session: DatabaseSession) -> dict:
    session.execute(text("BEGIN IMMEDIATE"))
    existing = session.get(AccessObservation, str(payload.request_id))
    fields = {
        "source_ip": payload.source_ip, "target": payload.target,
        "http_status": payload.http_status,
        "block_id": str(payload.block_id) if payload.block_id else None,
    }
    if existing is not None:
        if any(getattr(existing, key) != value for key, value in fields.items()):
            raise HTTPException(status_code=409, detail="request_id corresponde a otra observación")
        return existing.result

    expire_blocks(session)
    active = find_active_block(session, payload.source_ip, payload.target)
    block = None
    incident_status = None
    if payload.http_status == 403:
        if active is None or fields["block_id"] != active.id:
            raise HTTPException(status_code=409, detail="El rechazo no coincide con un bloqueo activo")
        block = active
        if block.verified_at is None:
            block.verified_at = utc_now()
            record_audit(
                session, "protected_app", "block_verified", block.source_ip, block.target,
                block.incident_id,
                f"El servicio protegido rechazó con HTTP 403. Solicitud {payload.request_id}.",
            )
        incident = session.get(Incident, block.incident_id)
        incident.status = "contained"
        incident_status = incident.status
    else:
        if active is not None:
            raise HTTPException(status_code=409, detail="No se puede verificar acceso permitido con bloqueo activo")
        if fields["block_id"] is not None:
            referenced = session.get(Block, fields["block_id"])
            if referenced is None or referenced.source_ip != payload.source_ip or referenced.target != payload.target:
                raise HTTPException(status_code=409, detail="El bloqueo no coincide con el origen de la observación")
        pending = session.scalars(
            select(Block).where(
                Block.source_ip == payload.source_ip, Block.target == payload.target,
                Block.status.in_(["released", "expired"]), Block.restored_at.is_(None),
            ).order_by(Block.created_at.desc())
        ).all()
        for released in pending:
            released.restored_at = utc_now()
            incident = session.get(Incident, released.incident_id)
            incident.status = "restored"
            incident_status = incident.status
            record_audit(
                session, "protected_app", "access_restored", released.source_ip,
                released.target, released.incident_id,
                f"El servicio protegido permitió HTTP 200. Solicitud {payload.request_id}.",
            )
        if pending:
            block = pending[0]

    result = {
        "recorded": True, "block_id": block.id if block else None,
        "incident_status": incident_status,
    }
    session.add(AccessObservation(
        id=str(payload.request_id), observed_at=utc_now(), result=result, **fields,
    ))
    session.commit()
    return result


@router.get("/blocks", dependencies=[Depends(require_admin_token)])
def list_blocks(session: DatabaseSession, active_only: bool = False) -> list[BlockItem]:
    expire_due_blocks(session)
    query = select(Block)
    if active_only:
        query = query.where(Block.status == "active", Block.expires_at > utc_now())
    return [serialize_block(block) for block in session.scalars(
        query.order_by(Block.created_at.desc()).limit(100)
    )]


@router.post("/blocks/{block_id}/release", dependencies=[Depends(require_admin_token)])
def release_block(block_id: UUID, session: DatabaseSession) -> BlockItem:
    session.execute(text("BEGIN IMMEDIATE"))
    expire_blocks(session)
    block = session.get(Block, str(block_id))
    if block is None:
        raise HTTPException(status_code=404, detail="Bloqueo no encontrado")
    if block.status != "active":
        raise HTTPException(status_code=409, detail="El bloqueo ya no está activo")
    release_containment(session, block)
    result = serialize_block(block)
    session.commit()
    return result


@router.post("/incidents/{incident_id}/respond", dependencies=[Depends(require_admin_token)])
def respond_incident(incident_id: UUID, request: Request, session: DatabaseSession) -> BlockItem:
    session.execute(text("BEGIN IMMEDIATE"))
    incident = session.get(Incident, str(incident_id))
    if incident is None:
        raise HTTPException(status_code=404, detail="Incidente no encontrado")
    block = create_block(session, incident, request.app.state.settings, "admin", "Solicitud manual autorizada.")
    if block is None:
        reason = incident.reason
        session.commit()
        raise HTTPException(status_code=409, detail=reason)
    result = serialize_block(block)
    session.commit()
    return result


@router.post("/incidents/{incident_id}/restore", dependencies=[Depends(require_admin_token)])
def restore_incident(incident_id: UUID, session: DatabaseSession) -> IncidentSummary:
    session.execute(text("BEGIN IMMEDIATE"))
    expire_blocks(session)
    incident = session.get(Incident, str(incident_id))
    if incident is None:
        raise HTTPException(status_code=404, detail="Incidente no encontrado")
    for block in session.scalars(select(Block).where(
        Block.incident_id == incident.id, Block.status == "active"
    )):
        release_containment(session, block)
    result = serialize_incident(incident)
    session.commit()
    return result


@router.get("/audit", dependencies=[Depends(require_admin_token)])
def list_audit(
    session: DatabaseSession, limit: Annotated[int, Query(ge=1, le=200)] = 50
) -> list[AuditItem]:
    entries = session.scalars(select(AuditEntry).order_by(AuditEntry.timestamp.desc()).limit(limit))
    return [AuditItem(
        id=entry.id, timestamp=entry.timestamp.replace(tzinfo=UTC), actor=entry.actor,
        action=entry.action, source_ip=entry.source_ip, target=entry.target,
        incident_id=entry.incident_id, detail=entry.detail,
    ) for entry in entries]


@router.get("/metrics", dependencies=[Depends(require_admin_token)])
def get_metrics(session: DatabaseSession) -> Metrics:
    expire_due_blocks(session)
    events = session.scalar(select(func.count()).select_from(SecurityEvent))
    incidents = session.scalar(select(func.count()).select_from(Incident))
    verified = session.scalar(select(func.count()).select_from(Block).where(Block.verified_at.is_not(None)))
    active = session.scalar(select(func.count()).select_from(Block).where(
        Block.status == "active", Block.expires_at > utc_now()
    ))
    restored = session.scalar(select(func.count()).select_from(Block).where(Block.restored_at.is_not(None)))
    return Metrics(
        events=events, incidents=incidents, alerts=incidents, verified_blocks=verified,
        active_blocks=active, restored_access=restored,
    )


@router.get("/system/status", dependencies=[Depends(require_admin_token)])
@router.get("/system", dependencies=[Depends(require_admin_token)])
def get_system(request: Request) -> dict:
    settings = request.app.state.settings
    return {
        "ai_enabled": settings.ai_enabled, "ai_model": settings.ai_model,
        "auto_containment": settings.auto_containment,
        "medium_threshold": settings.medium_threshold, "high_threshold": settings.high_threshold,
        "window_seconds": settings.window.total_seconds(),
        "block_seconds": settings.block_duration.total_seconds(),
        "lab_cidrs": [str(network) for network in settings.lab_networks],
        "allowlist": [str(network) for network in settings.allowlist],
        "max_active_blocks": settings.max_active_blocks,
        "protected_app_url": settings.protected_app_url,
    }
