from datetime import UTC, datetime
from secrets import compare_digest
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
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
from backend.containment import expire_blocks, find_active_block, record_audit, utc_now
from backend.detection import correlate
from backend.models import AuditEntry, Block, Incident, SecurityEvent

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
    return receipt


@router.get("/incidents", dependencies=[Depends(require_admin_token)])
def list_incidents(
    session: DatabaseSession,
    limit: Annotated[int, Query(ge=1, le=100)] = 30,
    offset: Annotated[int, Query(ge=0)] = 0,
    severity: Severity | None = None,
    status: IncidentStatus | None = None,
) -> IncidentPage:
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
        id=block.id,
        incident_id=block.incident_id,
        source_ip=block.source_ip,
        target=block.target,
        status=block.status,
        created_at=block.created_at.replace(tzinfo=UTC),
        expires_at=block.expires_at.replace(tzinfo=UTC),
        released_at=block.released_at.replace(tzinfo=UTC) if block.released_at else None,
    )


@router.get("/blocks/check", dependencies=[Depends(require_ingest_token)])
def check_block(source_ip: str, target: str, session: DatabaseSession) -> BlockStatus:
    """La app protegida pregunta aquí si una IP está bloqueada antes de revisar el login."""
    session.execute(text("BEGIN IMMEDIATE"))
    block = find_active_block(session, source_ip, target)
    if block is None:
        result = BlockStatus(blocked=False)
    else:
        result = BlockStatus(blocked=True, expires_at=block.expires_at.replace(tzinfo=UTC))
    session.commit()
    return result


@router.get("/blocks", dependencies=[Depends(require_admin_token)])
def list_blocks(session: DatabaseSession, active_only: bool = False) -> list[BlockItem]:
    session.execute(text("BEGIN IMMEDIATE"))
    expire_blocks(session)
    query = select(Block)
    if active_only:
        query = query.where(Block.status == "active")
    result = [serialize_block(b) for b in session.scalars(query.order_by(Block.created_at.desc()).limit(100))]
    session.commit()
    return result


@router.post("/blocks/{block_id}/release", dependencies=[Depends(require_admin_token)])
def release_block(block_id: UUID, session: DatabaseSession) -> BlockItem:
    session.execute(text("BEGIN IMMEDIATE"))
    block = session.get(Block, str(block_id))
    if block is None:
        raise HTTPException(status_code=404, detail="Bloqueo no encontrado")
    if block.status != "active":
        raise HTTPException(status_code=409, detail="El bloqueo ya no está activo")
    block.status = "released"
    block.released_at = utc_now()
    record_audit(
        session, "admin", "block_released", block.source_ip, block.target,
        block.incident_id, "Un administrador liberó el bloqueo manualmente.",
    )
    result = serialize_block(block)
    session.commit()
    return result


@router.get("/audit", dependencies=[Depends(require_admin_token)])
def list_audit(
    session: DatabaseSession, limit: Annotated[int, Query(ge=1, le=200)] = 50
) -> list[AuditItem]:
    entries = session.scalars(select(AuditEntry).order_by(AuditEntry.timestamp.desc()).limit(limit))
    return [
        AuditItem(
            id=e.id,
            timestamp=e.timestamp.replace(tzinfo=UTC),
            actor=e.actor,
            action=e.action,
            source_ip=e.source_ip,
            target=e.target,
            incident_id=e.incident_id,
            detail=e.detail,
        )
        for e in entries
    ]


@router.get("/metrics", dependencies=[Depends(require_admin_token)])
def get_metrics(session: DatabaseSession) -> Metrics:
    events = session.scalar(select(func.count()).select_from(SecurityEvent))
    incidents = session.scalar(select(func.count()).select_from(Incident))
    blocks = session.scalar(select(func.count()).select_from(Block))
    return Metrics(events=events, incidents=incidents, alerts=incidents, verified_blocks=blocks)