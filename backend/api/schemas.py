from datetime import UTC
from ipaddress import IPv6Address, ip_address
from typing import Literal
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, StrictBool, field_validator

Severity = Literal["low", "medium", "high"]
IncidentStatus = Literal["alert", "pending_containment", "pending_verification", "review", "contained", "restoration_pending", "restored"]
RecommendedAction = Literal["review", "temporary_block"]


class EventMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=128)
    success: StrictBool

    @field_validator("success")
    @classmethod
    def check_failure(cls, success: bool) -> bool:
        if success:
            raise ValueError("failed_login requiere success=false")
        return success


class EventPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_type: Literal["failed_login"]
    source_ip: str
    target: Literal["servidor-web"]
    timestamp: AwareDatetime
    metadata: EventMetadata

    @field_validator("source_ip")
    @classmethod
    def normalize_ip(cls, value: str) -> str:
        address = ip_address(value)
        if isinstance(address, IPv6Address):
            if address.scope_id is not None:
                raise ValueError("source_ip no admite identificadores de zona")
            if address.ipv4_mapped is not None:
                return str(address.ipv4_mapped)
        return str(address)

    @field_validator("timestamp", mode="before")
    @classmethod
    def require_iso_format(cls, value: object) -> object:
        if not isinstance(value, str) or "T" not in value:
            raise ValueError("timestamp debe ser ISO 8601 e incluir una zona horaria")
        return value

    @field_validator("timestamp")
    @classmethod
    def normalize_timestamp(cls, value: AwareDatetime) -> AwareDatetime:
        try:
            return value.astimezone(UTC)
        except OverflowError as exc:
            raise ValueError("timestamp fuera del rango admitido") from exc


class EventReceipt(BaseModel):
    event_id: UUID
    severity: Severity
    incident_id: UUID | None


class IncidentSummary(BaseModel):
    id: UUID
    category: Literal["possible_brute_force", "possible_password_spraying"] = "possible_brute_force"
    source_ip: str
    target: str
    severity: Severity
    status: IncidentStatus
    first_seen: AwareDatetime
    last_seen: AwareDatetime
    event_count: int
    attempts: int
    recommended_action: RecommendedAction
    reason: str


class EventEvidence(BaseModel):
    id: UUID
    event_type: Literal["failed_login"]
    source_ip: str
    target: str
    timestamp: AwareDatetime
    metadata: EventMetadata
    severity: Severity


class IncidentDetail(IncidentSummary):
    events: list[EventEvidence]


class IncidentPage(BaseModel):
    items: list[IncidentSummary]
    total: int


class Metrics(BaseModel):
    events: int
    incidents: int
    alerts: int
    verified_blocks: int
    active_blocks: int
    restored_access: int
