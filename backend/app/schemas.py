"""API request/response schemas for sessions & assignments."""
from __future__ import annotations

import re

from pydantic import BaseModel, Field, model_validator


# -- inventory: controllers & targets ----------------------------------------
def validate_controller_auth(platform: str, base_url, api_client_id, api_client_secret,
                             api_username, api_password, api_version, tenant_id=None) -> None:
    """Shared platform-auth check (used by create and update)."""
    if platform not in ("r1", "sz"):
        raise ValueError("platform must be 'r1' or 'sz'")
    if platform == "r1":
        if not (api_client_id and api_client_secret):
            raise ValueError("Ruckus One needs api_client_id and api_client_secret")
        if not tenant_id:
            raise ValueError("Ruckus One needs tenant_id (used in the OAuth token call)")
    else:
        if not (base_url and api_username and api_password and api_version):
            raise ValueError("SmartZone needs base_url, api_username, api_password, api_version")
        if not re.fullmatch(r"v\d+_\d+", api_version):
            raise ValueError("api_version must look like vMAJOR_MINOR, e.g. v13_0")


class ControllerCreate(BaseModel):
    platform: str = Field(description="r1 | sz")
    name: str
    base_url: str | None = None
    region: str | None = None
    tenant_id: str | None = None
    api_client_id: str | None = None      # R1
    api_client_secret: str | None = None  # R1
    api_username: str | None = None       # SZ
    api_password: str | None = None       # SZ
    api_version: str | None = Field(default=None, description="SmartZone API version, e.g. v13_0")

    @model_validator(mode="after")
    def _platform_auth(self):
        validate_controller_auth(self.platform, self.base_url, self.api_client_id,
                                 self.api_client_secret, self.api_username,
                                 self.api_password, self.api_version, self.tenant_id)
        return self


class ControllerUpdate(BaseModel):
    """Partial update. Secret fields (api_client_secret / api_password) are applied
    only when non-empty — leave blank to keep the stored value."""
    name: str | None = None
    base_url: str | None = None
    region: str | None = None
    tenant_id: str | None = None
    api_client_id: str | None = None
    api_client_secret: str | None = None
    api_username: str | None = None
    api_password: str | None = None
    api_version: str | None = None


class ControllerOut(BaseModel):
    id: str
    platform: str
    name: str
    base_url: str | None
    region: str | None
    tenant_id: str | None
    api_client_id: str | None     # non-secret identifier (shown for edit prefill)
    api_username: str | None      # non-secret identifier
    api_version: str | None
    has_api_creds: bool           # secrets are never echoed back
    target_count: int = 0
    created_at: str


class TargetCreate(BaseModel):
    name: str
    host: str = Field(description="AP management IP")
    model: str | None = None
    serial: str | None = None
    controller_id: str | None = None
    ssh_username: str | None = None   # optional per-AP override
    ssh_password: str | None = None
    notes: str | None = None


class TargetUpdate(BaseModel):
    """Partial update. ssh_password applied only when non-empty (blank = keep)."""
    name: str | None = None
    host: str | None = None
    model: str | None = None
    serial: str | None = None
    controller_id: str | None = None
    ssh_username: str | None = None
    ssh_password: str | None = None
    notes: str | None = None


class TargetOut(BaseModel):
    id: str
    name: str
    host: str
    model: str | None
    firmware: str | None = None
    serial: str | None
    controller_id: str | None
    controller_name: str | None
    controller_platform: str | None = None   # r1 | sz — drives capture-mode UI
    suggested_host_ip: str | None = None      # tool host IP reachable from this AP
    ssh_username: str | None         # raw per-AP override (for edit prefill)
    ssh_username_effective: str      # resolved override -> env default
    has_stored_password: bool        # a password stored on the target (else env fallback)
    notes: str | None
    created_at: str


# SmartZone capture modes; ssh backend / R1 ignore this and use rkscli+rpcap.
CAPTURE_MODES = ("file", "stream_wireshark", "stream_inapp")


class AssignmentCreate(BaseModel):
    target_id: str = Field(description="a stored capture target (add it under Inventory first)")
    iface: str = Field(default="wifi0", description="wifi0=2.4, wifi1=5, wifi2=6")
    target_channel: int | None = Field(default=None, description="pinned via CLI before capture")
    width_mhz: int | None = Field(default=None, description="20/40/80/160; null = AP default")
    flags: str = Field(default="", description="rkscli capture flags, e.g. -nob")
    capture_mode: str = Field(default="file", description="SZ: file | stream_wireshark | stream_inapp")
    host_ip: str | None = Field(default=None, description="Wireshark/tool host IP for streaming modes")


class SessionCreate(BaseModel):
    name: str
    notes: str | None = None


class SessionStart(BaseModel):
    duration_s: int | None = Field(default=None, ge=1, description="auto-stop all after N seconds")


class AssignmentOut(BaseModel):
    id: str
    ap_host: str
    target_id: str | None = None
    iface: str
    target_channel: int | None
    width_mhz: int | None = None
    flags: str
    capture_mode: str = "file"
    status: str
    channel: int | None
    linktype: int | None
    frames: int
    bytes: int
    has_file: bool
    error: str | None
    started_at: str | None
    ended_at: str | None
    # live overlay (present only while running in-process)
    elapsed_s: float | None = None
    seconds_since_last_frame: float | None = None
    stream_url: str | None = None    # rpcap:// URL for Wireshark (stream_wireshark mode)


class SessionTotals(BaseModel):
    assignments: int = 0
    active: int = 0
    done: int = 0
    failed: int = 0
    frames: int = 0
    bytes: int = 0


class VenueOut(BaseModel):
    external_id: str
    name: str
    address: str | None = None


class ApInventoryOut(BaseModel):
    serial: str
    name: str
    model: str | None = None
    mac: str | None = None
    ip: str | None = None
    firmware: str | None = None
    state: str | None = None
    venue_id: str | None = None
    already_target: bool = False   # already imported (by serial)


class ImportRequest(BaseModel):
    venue_id: str
    serials: list[str] = Field(min_length=1)
    ssh_password: str | None = Field(
        default=None, description="applied to imported APs when the controller has no "
                                  "per-AP password API (e.g. SmartZone static/shared login)")


class ArtifactOut(BaseModel):
    id: str
    kind: str
    size_bytes: int
    sha256: str | None
    created_at: str
    meta: dict | None = None


class SessionOut(BaseModel):
    id: str
    name: str
    status: str
    notes: str | None
    created_at: str
    started_at: str | None
    ended_at: str | None
    totals: SessionTotals
    assignments: list[AssignmentOut]
    artifacts: list[ArtifactOut] = []


class MergeRequest(BaseModel):
    assignment_ids: list[str] | None = Field(
        default=None, description="subset to merge; default = all completed assignments")


class TemplateCreate(BaseModel):
    name: str
    description: str | None = None
    assignments: list[AssignmentCreate]


class SaveTemplate(BaseModel):
    name: str | None = None
    description: str | None = None


class Instantiate(BaseModel):
    name: str | None = None


class TemplateOut(BaseModel):
    id: str
    name: str
    description: str | None
    assignments: list[AssignmentCreate]
    created_at: str
