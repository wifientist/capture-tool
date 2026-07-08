"""Sidecar JSON writer — provenance for each capture (see docs schema)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .orchestrator import CaptureJob


def build_sidecar(job: "CaptureJob") -> dict[str, Any]:
    st = job.reader.stats if job.reader else job.stats
    duration = None
    if st and st.first_ts and st.last_ts:
        duration = round(st.last_ts - st.first_ts, 3)
    offset_ms = None
    if job.ap_epoch_ms_at_start and job.server_epoch_ms_at_start:
        offset_ms = job.ap_epoch_ms_at_start - job.server_epoch_ms_at_start
    return {
        "capture_id": job.id,
        "name": job.name,
        "ap": {"mgmt_ip": job.ap_host},
        "radio": {"iface": job.iface, "channel": job.channel,
                  "linktype": st.linktype if st else None},
        "capture": {
            "mode": "stream",
            "flags": job.flags,
            "started_at": job.started_at,
            "ended_at": job.ended_at,
            "frames": st.frames if st else 0,
            "bytes": st.bytes if st else 0,
            "duration_s": duration,
            "truncated": bool(st and (st.error or st.capped)),
            "capped_at_max_bytes": bool(st and st.capped),
        },
        "clock": {
            "ap_epoch_ms_at_start": job.ap_epoch_ms_at_start,
            "server_epoch_ms_at_start": job.server_epoch_ms_at_start,
            "offset_ms": offset_ms,
            # APs are NTP-synced -> frame timestamps share a common reference, so
            # cross-AP merges align without per-AP offset correction. offset_ms is a
            # best-effort cross-check only (null when no rkscli clock source is available).
            "alignment": "assume_ntp_synced",
        },
        "ssh": {"host_key_fingerprint": job.host_key_fingerprint},
        "state": job.state.value,
        "error": job.error or (st.error if st else None),
    }


def write_sidecar(job: "CaptureJob", path: Path) -> dict[str, Any]:
    data = build_sidecar(job)
    path.write_text(json.dumps(data, indent=2))
    return data
