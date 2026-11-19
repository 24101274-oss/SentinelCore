import os
from dataclasses import dataclass
from datetime import timedelta
from ipaddress import IPv4Network, IPv6Network, ip_network

Network = IPv4Network | IPv6Network


def read_networks(name: str) -> tuple[Network, ...]:
    try:
        return tuple(
            ip_network(value.strip())
            for value in os.getenv(name, "").split(",")
            if value.strip()
        )
    except ValueError as exc:
        raise ValueError(f"{name} debe contener direcciones IP o redes CIDR separadas por coma") from exc


@dataclass(frozen=True)
class Settings:
    ingest_token: str
    admin_token: str
    database_url: str = "sqlite:///./data/sentinelcore.db"
    window: timedelta = timedelta(seconds=60)
    medium_threshold: int = 3
    high_threshold: int = 5
    allowlist: tuple[Network, ...] = ()
    lab_networks: tuple[Network, ...] = ()
    auto_containment: bool = True
    block_duration: timedelta = timedelta(minutes=10)
    ai_enabled: bool = False
    ai_base_url: str = "https://api.groq.com/openai/v1"
    ai_api_key: str = ""
    ai_model: str = "openai/gpt-oss-20b"
    ai_min_confidence: float = 0.8

    def __post_init__(self) -> None:
        if not self.ingest_token.strip() or not self.admin_token.strip():
            raise ValueError("Configura INGEST_TOKEN y ADMIN_TOKEN para iniciar la API")
        if self.ingest_token == self.admin_token:
            raise ValueError("INGEST_TOKEN y ADMIN_TOKEN deben ser distintos")
        if self.window <= timedelta(0) or not 0 < self.medium_threshold < self.high_threshold:
            raise ValueError("Se requiere WINDOW_SECONDS > 0 y 0 < MEDIUM_THRESHOLD < HIGH_THRESHOLD")
        if self.block_duration <= timedelta(0):
            raise ValueError("BLOCK_SECONDS debe ser mayor que 0")
        if self.ai_enabled and not self.ai_api_key.strip():
            raise ValueError("Configura AI_API_KEY para usar AI_ENABLED=true")

    @classmethod
    def from_environment(cls) -> "Settings":
        return cls(
            ingest_token=os.getenv("INGEST_TOKEN", ""),
            admin_token=os.getenv("ADMIN_TOKEN", ""),
            database_url=os.getenv("DATABASE_URL", cls.database_url),
            window=timedelta(seconds=int(os.getenv("WINDOW_SECONDS", "60"))),
            medium_threshold=int(os.getenv("MEDIUM_THRESHOLD", "3")),
            high_threshold=int(os.getenv("HIGH_THRESHOLD", "5")),
            allowlist=read_networks("ALLOWLIST"),
            lab_networks=read_networks("LAB_CIDRS"),
            auto_containment=os.getenv("AUTO_CONTAINMENT", "true").strip().lower() in ("1", "true", "yes", "on"),
            block_duration=timedelta(seconds=int(os.getenv("BLOCK_SECONDS", "600"))),
            ai_enabled=os.getenv("AI_ENABLED", "false").strip().lower() in ("1", "true", "yes", "on"),
            ai_base_url=os.getenv("AI_BASE_URL", cls.ai_base_url).rstrip("/"),
            ai_api_key=os.getenv("AI_API_KEY", ""),
            ai_model=os.getenv("AI_MODEL", cls.ai_model),
            ai_min_confidence=float(os.getenv("AI_MIN_CONFIDENCE", "0.8")),
        )