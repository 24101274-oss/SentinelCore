from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (Index("incident_scope_time", "source_ip", "target", "last_seen"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    source_ip: Mapped[str] = mapped_column(String(45))
    target: Mapped[str] = mapped_column(String(100))
    severity: Mapped[str] = mapped_column(String(6))
    status: Mapped[str] = mapped_column(String(20))
    first_seen: Mapped[datetime] = mapped_column(DateTime)
    last_seen: Mapped[datetime] = mapped_column(DateTime)
    event_count: Mapped[int] = mapped_column(Integer)
    attempts: Mapped[int] = mapped_column(Integer)
    recommended_action: Mapped[str] = mapped_column(String(20))
    reason: Mapped[str] = mapped_column(String(300))


class SecurityEvent(Base):
    __tablename__ = "security_events"
    __table_args__ = (Index("event_scope_time", "source_ip", "target", "timestamp"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    event_type: Mapped[str] = mapped_column(String(30))
    source_ip: Mapped[str] = mapped_column(String(45))
    target: Mapped[str] = mapped_column(String(100))
    timestamp: Mapped[datetime] = mapped_column(DateTime)
    details: Mapped[dict] = mapped_column("metadata", JSON)
    severity: Mapped[str] = mapped_column(String(6))
    # El incidente del recibo original no cambia si aparecen más evidencias.
    receipt_incident_id: Mapped[str | None] = mapped_column(ForeignKey("incidents.id"))
    incident_id: Mapped[str | None] = mapped_column(ForeignKey("incidents.id"), index=True)
class Block(Base):
    __tablename__ = "blocks"
    __table_args__ = (Index("block_lookup", "source_ip", "target", "status"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.id"), index=True)
    source_ip: Mapped[str] = mapped_column(String(45))
    target: Mapped[str] = mapped_column(String(100))
    status: Mapped[str] = mapped_column(String(10))  # active, expired, released
    created_at: Mapped[datetime] = mapped_column(DateTime)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    released_at: Mapped[datetime | None] = mapped_column(DateTime)


class AuditEntry(Base):
    __tablename__ = "audit_log"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime)
    actor: Mapped[str] = mapped_column(String(30))  # system, admin
    action: Mapped[str] = mapped_column(String(30))  # block_created, block_expired, block_released
    source_ip: Mapped[str] = mapped_column(String(45))
    target: Mapped[str] = mapped_column(String(100))
    incident_id: Mapped[str | None] = mapped_column(ForeignKey("incidents.id"))
    detail: Mapped[str] = mapped_column(String(300))
