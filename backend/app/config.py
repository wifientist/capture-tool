"""Runtime configuration. Secrets come from the environment (.env for local)."""
from __future__ import annotations

import socket
from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CT_", env_file=".env", extra="ignore")

    # AP SSH access (password rotates -> keep in env, never on disk)
    ap_username: str = "admin"
    ap_password: str = Field(default="", description="rkscli password (CT_AP_PASSWORD)")

    # persistence — sqlite for the venv slice; Postgres in Docker (CT_DATABASE_URL)
    database_url: str | None = None

    # capture host
    capture_dir: Path = Path(__file__).resolve().parents[2] / "data" / "captures"
    host_ip: str | None = None  # override the local IP advertised to rpcapd

    # engine tunables
    rpcap_port: int = 2002
    heartbeat_timeout_s: int = 30
    snaplen: int = 65535
    default_max_duration_s: int = 120          # cap open-ended sessions (blank duration)
    max_capture_bytes: int = 2_000_000_000     # ~2 GB per pcap safety cap
    arm_timeout_s: int = 600                    # Wireshark-stream: max wait for the analyst to arm

    def resolve_database_url(self) -> str:
        if self.database_url:
            return self.database_url
        return f"sqlite+aiosqlite:///{self.capture_dir.parent / 'capture_tool.db'}"

    def local_ip_for(self, ap_host: str) -> str:
        """The local address that routes to the AP — advertised to rpcapd as the
        stream target. Overridable via CT_HOST_IP for multi-homed hosts."""
        if self.host_ip:
            return self.host_ip
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((ap_host, 9))
            return s.getsockname()[0]
        finally:
            s.close()


@lru_cache
def get_settings() -> Settings:
    s = get_settings_uncached()
    s.capture_dir.mkdir(parents=True, exist_ok=True)
    return s


def get_settings_uncached() -> Settings:
    return Settings()
