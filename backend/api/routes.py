from datetime import UTC
from secrets import compare_digest
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
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
from backend.detection import correlate
from backend.models import Incident, SecurityEvent

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


@router.get("/metrics", dependencies=[Depends(require_admin_token)])
def get_metrics(session: DatabaseSession) -> Metrics:
    events = session.scalar(select(func.count()).select_from(SecurityEvent))
    incidents = session.scalar(select(func.count()).select_from(Incident))
    return Metrics(events=events, incidents=incidents, alerts=incidents, verified_blocks=0)
