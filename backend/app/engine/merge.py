"""Time-aligned pcap merge. Originals are never modified — a new file is written.

Prefers `mergecap` (wireshark-common; present in the Docker image). Falls back to a
pure-Python timestamp merge when mergecap is absent (the venv slice) — safe here
because all AP captures share one link-type (DLT_PPI = 192). Cross-AP alignment
relies on the APs being NTP-synced (see sidecar `clock.alignment`).
"""
from __future__ import annotations

import hashlib
import heapq
import shutil
import struct
import subprocess
from pathlib import Path
from typing import Iterator


class MergeError(Exception):
    pass


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _read_global(f) -> tuple[str, int]:
    """Return (struct-endian-prefix, linktype) from a classic pcap global header."""
    magic = f.read(4)
    # On-disk byte order of the canonical 0xA1B2C3D4 magic tells us the file's endianness.
    if magic == b"\xd4\xc3\xb2\xa1":       # little-endian writer
        end = "<"
    elif magic == b"\xa1\xb2\xc3\xd4":     # big-endian writer
        end = ">"
    else:
        raise MergeError("not a classic pcap file (unsupported magic)")
    _vmaj, _vmin, _tz, _sig, _snap, linktype = struct.unpack(end + "HHiIII", f.read(20))
    return end, linktype


def _iter_records(path: Path) -> Iterator[tuple[int, int, bytes]]:
    """Yield (ts_sec, ts_usec, raw_record_bytes_LE) with each record re-emitted
    little-endian so the merged file is uniformly little-endian."""
    with open(path, "rb") as f:
        end, linktype = _read_global(f)
        while True:
            hdr = f.read(16)
            if len(hdr) < 16:
                break
            ts_sec, ts_usec, incl, orig = struct.unpack(end + "IIII", hdr)
            data = f.read(incl)
            if len(data) < incl:
                break
            rec = struct.pack("<IIII", ts_sec, ts_usec, incl, orig) + data
            yield ts_sec, ts_usec, rec


def _linktype_of(path: Path) -> int:
    with open(path, "rb") as f:
        return _read_global(f)[1]


def _classic_linktype(path: Path) -> int | None:
    """Link-type if *path* is a classic pcap; None if it's pcapng / not classic /
    unreadable. Used to decide the merge output format."""
    try:
        with open(path, "rb") as f:
            if f.read(4) not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
                return None
            f.seek(0)
            return _read_global(f)[1]
    except (OSError, MergeError, struct.error):
        return None


def _python_merge(inputs: list[Path], out: Path) -> None:
    linktypes = {_linktype_of(p) for p in inputs}
    if len(linktypes) > 1:
        raise MergeError(f"mixed link-types {linktypes}; install mergecap for pcapng merge")
    linktype = linktypes.pop()
    snaplen = 65535
    streams = [_iter_records(p) for p in inputs]  # each yields (ts_sec, ts_usec, rec)
    with open(out, "wb") as w:
        w.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, linktype))
        for _s, _u, rec in heapq.merge(*streams, key=lambda r: (r[0], r[1])):
            w.write(rec)


def analyze_alignment(inputs: list[Path]) -> dict:
    """Per-capture timestamp range + cross-capture alignment. Captures from one
    session start together, so on NTP-synced APs their first-frame timestamps
    should be close; a large spread flags clock skew (or very staggered starts)."""
    per = []
    for p in inputs:
        if _classic_linktype(p) is None:
            # pcapng / non-classic input: our lightweight record walker can't parse
            # it. Alignment is best-effort metadata, so note it and move on.
            per.append({"name": p.name, "frames": None, "first_ts": None,
                        "last_ts": None, "duration_s": 0.0,
                        "note": "non-classic pcap — alignment not analyzed"})
            continue
        first = last = None
        n = 0
        for s, u, _rec in _iter_records(p):
            t = s + u / 1e6
            if first is None:
                first = t
            last = t
            n += 1
        per.append({"name": p.name, "frames": n,
                    "first_ts": first, "last_ts": last,
                    "duration_s": round(last - first, 3) if (first and last) else 0.0})
    firsts = [x["first_ts"] for x in per if x["first_ts"] is not None]
    lasts = [x["last_ts"] for x in per if x["last_ts"] is not None]
    summary: dict = {"inputs": len(per)}
    if firsts and lasts:
        start_spread = round(max(firsts) - min(firsts), 3)
        overlap = round(max(0.0, min(lasts) - max(firsts)), 3)
        summary.update({
            "start_spread_s": start_spread,
            "end_spread_s": round(max(lasts) - min(lasts), 3),
            "overlap_s": overlap,
            # heuristic: aligned if starts within ~1s and there is real overlap
            "aligned": start_spread < 1.0 and overlap > 0,
        })
    return {"summary": summary, "per_input": per}


def merge_pcaps(inputs: list[Path], out: Path) -> dict:
    """Merge *inputs* (time-ordered) into *out*. Returns artifact metadata,
    including the actual output path (``path``) and format (``format``).

    Classic pcap holds a single global link-type, so it can only represent inputs
    that all share one link-type. Our captures don't: SSH/rkscli emit DLT_PPI
    (192), SmartZone streaming taps present radiotap (127), and SZ file captures
    vary by model/firmware. Feeding mixed link-types to `mergecap -F pcap` fails
    with "can't be written as a pcap file". So we emit pcapng (per-interface
    link-types) whenever the inputs aren't one uniform classic-pcap link-type, and
    keep classic pcap only for the uniform case (widest tool compatibility)."""
    inputs = [Path(p) for p in inputs if Path(p).exists()]
    if not inputs:
        raise MergeError("no input pcaps to merge")
    out = Path(out)

    lts = [_classic_linktype(p) for p in inputs]
    uniform_pcap = all(lt is not None for lt in lts) and len({*lts}) == 1
    fmt = "pcap" if uniform_pcap else "pcapng"
    if fmt == "pcapng":
        out = out.with_suffix(".pcapng")

    if shutil.which("mergecap"):
        tool = "mergecap"
        cmd = ["mergecap", "-F", fmt, "-w", str(out), *map(str, inputs)]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            raise MergeError(f"mergecap failed: {proc.stderr.strip()[:200]}")
    elif uniform_pcap:
        tool = "python"
        _python_merge(inputs, out)
    else:
        classic = sorted({lt for lt in lts if lt is not None})
        raise MergeError(
            f"inputs have mixed link-types (classic {classic}"
            + (" plus pcapng/non-classic input" if any(lt is None for lt in lts) else "")
            + ") — install mergecap to merge them into a pcapng")
    return {
        "tool": tool,
        "format": fmt,
        "path": str(out),
        "inputs": [p.name for p in inputs],
        "size_bytes": out.stat().st_size,
        "sha256": _sha256(out),
        "alignment": analyze_alignment(inputs),
    }
