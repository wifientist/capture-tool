"""API/data models for the capture engine (in-memory slice; Postgres comes later)."""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class CaptureState(str, Enum):
    pending = "pending"
    configuring = "configuring"
    confirming_radio = "confirming_radio"
    capturing = "capturing"
    finalizing = "finalizing"
    done = "done"
    failed = "failed"
    cancelled = "cancelled"


class CaptureSpec(BaseModel):
    ap_host: str = Field(description="AP management IP")
    iface: str = Field(default="wifi0", description="wifi0=2.4, wifi1=5, wifi2=6")
    duration_s: int | None = Field(default=None, ge=1, description="auto-stop after N seconds")
    flags: str = Field(default="", description="rkscli capture flags, e.g. -nob")
    target_channel: int | None = Field(default=None, description="pin this channel via CLI before capture")
    width_mhz: int | None = Field(default=None, description="channel width 20/40/80/160; null=AP default")
    name: str | None = None
    # per-capture SSH creds (resolved from target/controller); fall back to settings if None
    ssh_username: str | None = None
    ssh_password: str | None = None
    # capture backend: "ssh" (rkscli+rpcap) or "sz_api" (SmartZone controller capture)
    backend: str = "ssh"
    sz_base_url: str | None = None
    sz_username: str | None = None
    sz_password: str | None = None
    sz_version: str | None = None
    sz_ap_mac: str | None = None
    # SmartZone capture mode: "file" | "stream_wireshark" | "stream_inapp"
    sz_capture_mode: str = "file"
    sz_host_ip: str | None = None   # Wireshark/tool host IP for streaming modes


class CaptureStatus(BaseModel):
    id: str
    name: str | None
    state: CaptureState
    ap_host: str
    iface: str
    channel: int | None = None
    linktype: int | None = None
    frames: int = 0
    bytes: int = 0
    elapsed_s: float = 0.0
    seconds_since_last_frame: float | None = None
    duration_s: int | None = None
    started_at: str | None = None
    ended_at: str | None = None
    error: str | None = None
    has_file: bool = False
    # streaming modes: rpcap URL for the analyst's Wireshark (stream_wireshark)
    stream_url: str | None = None
