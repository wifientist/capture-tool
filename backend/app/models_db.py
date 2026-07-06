"""ORM models: a capture Session groups Assignments (AP + radio + channel)."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


class Controller(Base):
    """A managing controller (Ruckus One or SmartZone).

    API auth is platform-specific:
      * R1 — OAuth2 API key: api_client_id + api_client_secret (region/tenant optional).
      * SZ — session login: base_url + api_username + api_password + api_version (vX_y).
    The controller holds NO AP SSH creds — AP CLI logins are unique per AP and are
    stored on the target (and can be pulled from the controller's API per-AP later).
    """
    __tablename__ = "controllers"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    platform: Mapped[str] = mapped_column(String(8))          # r1 | sz
    name: Mapped[str] = mapped_column(String(200))
    base_url: Mapped[str | None] = mapped_column(String(255), default=None)
    region: Mapped[str | None] = mapped_column(String(40), default=None)
    tenant_id: Mapped[str | None] = mapped_column(String(120), default=None)
    # R1 API auth
    api_client_id: Mapped[str | None] = mapped_column(String(255), default=None)
    api_client_secret: Mapped[str | None] = mapped_column(Text, default=None)
    # SZ API auth
    api_username: Mapped[str | None] = mapped_column(String(120), default=None)
    api_password: Mapped[str | None] = mapped_column(Text, default=None)
    api_version: Mapped[str | None] = mapped_column(String(16), default=None)  # e.g. v13_0
    created_at: Mapped[str] = mapped_column(String(40), default=_now_iso)

    targets: Mapped[list["Target"]] = relationship(
        back_populates="controller", lazy="selectin")


class Target(Base):
    """A capture-target AP. SSH creds resolve target-override -> controller -> env."""
    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    host: Mapped[str] = mapped_column(String(64))            # mgmt IP
    model: Mapped[str | None] = mapped_column(String(40), default=None)
    serial: Mapped[str | None] = mapped_column(String(64), default=None)
    controller_id: Mapped[str | None] = mapped_column(
        ForeignKey("controllers.id", ondelete="SET NULL"), default=None)
    venue_id: Mapped[str | None] = mapped_column(String(64), default=None)   # for R1 pw refresh
    ssh_username: Mapped[str | None] = mapped_column(String(64), default=None)   # override
    ssh_password: Mapped[str | None] = mapped_column(Text, default=None)         # override
    notes: Mapped[str | None] = mapped_column(Text, default=None)
    created_at: Mapped[str] = mapped_column(String(40), default=_now_iso)

    controller: Mapped["Controller | None"] = relationship(
        back_populates="targets", lazy="selectin")


class CaptureSession(Base):
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    # draft | running | stopping | done | failed
    status: Mapped[str] = mapped_column(String(20), default="draft")
    notes: Mapped[str | None] = mapped_column(Text, default=None)
    created_at: Mapped[str] = mapped_column(String(40), default=_now_iso)
    started_at: Mapped[str | None] = mapped_column(String(40), default=None)
    ended_at: Mapped[str | None] = mapped_column(String(40), default=None)

    assignments: Mapped[list["Assignment"]] = relationship(
        back_populates="session", cascade="all, delete-orphan",
        order_by="Assignment.created_at", lazy="selectin")


class Assignment(Base):
    __tablename__ = "assignments"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id", ondelete="CASCADE"))
    target_id: Mapped[str | None] = mapped_column(
        ForeignKey("targets.id", ondelete="SET NULL"), default=None)
    ap_host: Mapped[str] = mapped_column(String(64))   # denormalized from target at add time
    iface: Mapped[str] = mapped_column(String(16))
    target_channel: Mapped[int | None] = mapped_column(default=None)
    width_mhz: Mapped[int | None] = mapped_column(default=None)   # 20/40/80/160; null=AP default
    flags: Mapped[str] = mapped_column(String(32), default="")

    # pending|configuring|capturing|finalizing|done|failed|cancelled
    status: Mapped[str] = mapped_column(String(20), default="pending")
    channel: Mapped[int | None] = mapped_column(default=None)   # actual, from AP
    linktype: Mapped[int | None] = mapped_column(default=None)
    frames: Mapped[int] = mapped_column(default=0)
    bytes: Mapped[int] = mapped_column(default=0)
    file_path: Mapped[str | None] = mapped_column(Text, default=None)
    sidecar: Mapped[dict | None] = mapped_column(JSON, default=None)
    host_key_fingerprint: Mapped[str | None] = mapped_column(String(120), default=None)
    error: Mapped[str | None] = mapped_column(Text, default=None)
    created_at: Mapped[str] = mapped_column(String(40), default=_now_iso)
    started_at: Mapped[str | None] = mapped_column(String(40), default=None)
    ended_at: Mapped[str | None] = mapped_column(String(40), default=None)

    session: Mapped["CaptureSession"] = relationship(back_populates="assignments")


class Template(Base):
    __tablename__ = "templates"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str | None] = mapped_column(Text, default=None)
    # list of {ap_host, iface, target_channel, flags}
    assignments: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[str] = mapped_column(String(40), default=_now_iso)


class Artifact(Base):
    __tablename__ = "artifacts"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String(24))   # merged_pcap
    file_path: Mapped[str] = mapped_column(Text)
    size_bytes: Mapped[int] = mapped_column(default=0)
    sha256: Mapped[str | None] = mapped_column(String(64), default=None)
    meta: Mapped[dict | None] = mapped_column(JSON, default=None)
    created_at: Mapped[str] = mapped_column(String(40), default=_now_iso)
