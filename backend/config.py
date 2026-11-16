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

    def __post_init__(self) -> None:
        if not self.ingest_token.strip() or not self.admin_token.strip():
            raise ValueError("Configura INGEST_TOKEN y ADMIN_TOKEN para iniciar la API")
        if self.ingest_token == self.admin_token:
            raise ValueError("INGEST_TOKEN y ADMIN_TOKEN deben ser distintos")
        if self.window <= timedelta(0) or not 0 < self.medium_threshold < self.high_threshold:
            raise ValueError("Se requiere WINDOW_SECONDS > 0 y 0 < MEDIUM_THRESHOLD < HIGH_THRESHOLD")

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
        )
