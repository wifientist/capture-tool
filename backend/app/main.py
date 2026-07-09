"""FastAPI surface: session/assignment orchestration over the capture engine."""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse

from .config import get_settings
from .db import Database
from .engine.orchestrator import Engine
from .models import CaptureSpec, CaptureState, CaptureStatus
from .schemas import (ApInventoryOut, ArtifactOut, AssignmentCreate, ControllerCreate,
                      ControllerOut, ControllerUpdate, ImportRequest, Instantiate,
                      MergeRequest, SaveTemplate, SessionCreate, SessionOut, SessionStart,
                      SurveyOut, TargetCreate, TargetOut, TargetUpdate, TemplateCreate,
                      TemplateOut, VenueOut)
from .service import SessionService

STATIC = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    db = Database(settings.resolve_database_url())
    await db.create_all()  # dev convenience; Docker runs `alembic upgrade head` first
    engine = Engine(settings)
    service = SessionService(db, engine)
    orphaned = await service.reconcile_startup()
    if orphaned:
        print(f"[reconcile] failed {orphaned} orphaned assignment(s) from a prior run")
    app.state.settings = settings
    app.state.db = db
    app.state.engine = engine
    app.state.service = service
    try:
        yield
    finally:
        await service.shutdown()
        await engine.shutdown()
        await db.dispose()


app = FastAPI(title="Wi-Fi Capture Orchestrator", lifespan=lifespan)


def svc(app: FastAPI) -> SessionService:
    return app.state.service


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return (STATIC / "index.html").read_text()


@app.get("/api/health")
async def health() -> dict:
    s = app.state.settings
    return {"ok": True, "ap_password_fallback_set": bool(s.ap_password),
            "capture_dir": str(s.capture_dir)}


# -- inventory: controllers ---------------------------------------------------
@app.get("/api/controllers", response_model=list[ControllerOut])
async def list_controllers() -> list[ControllerOut]:
    return await app.state.service.list_controllers()


@app.post("/api/controllers", response_model=ControllerOut)
async def create_controller(spec: ControllerCreate) -> ControllerOut:
    return await app.state.service.create_controller(spec)


@app.put("/api/controllers/{cid}", response_model=ControllerOut)
async def update_controller(cid: str, patch: ControllerUpdate) -> ControllerOut:
    try:
        return await app.state.service.update_controller(
            cid, patch.model_dump(exclude_unset=True))
    except KeyError:
        raise HTTPException(404, "unknown controller")
    except ValueError as e:
        raise HTTPException(422, str(e))


@app.delete("/api/controllers/{cid}")
async def delete_controller(cid: str) -> JSONResponse:
    await app.state.service.delete_controller(cid)
    return JSONResponse({"deleted": cid})


# -- R1 import: browse venues/APs and pull into targets -----------------------
@app.get("/api/controllers/{cid}/venues", response_model=list[VenueOut])
async def controller_venues(cid: str) -> list[VenueOut]:
    try:
        return await app.state.service.list_controller_venues(cid)
    except KeyError:
        raise HTTPException(404, "unknown controller")
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(502, f"controller API error: {e}")


@app.get("/api/controllers/{cid}/venues/{venue_id}/aps", response_model=list[ApInventoryOut])
async def controller_venue_aps(cid: str, venue_id: str) -> list[ApInventoryOut]:
    try:
        return await app.state.service.list_controller_venue_aps(cid, venue_id)
    except KeyError:
        raise HTTPException(404, "unknown controller")
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(502, f"controller API error: {e}")


@app.get("/api/controllers/{cid}/venues/{venue_id}/survey", response_model=SurveyOut)
async def controller_venue_survey(cid: str, venue_id: str) -> SurveyOut:
    """Investigate: on-air survey of a zone/venue — AP channels + active WLANs."""
    try:
        return await app.state.service.survey_venue(cid, venue_id)
    except KeyError:
        raise HTTPException(404, "unknown controller")
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(502, f"controller API error: {e}")


@app.post("/api/controllers/{cid}/import", response_model=list[TargetOut])
async def import_targets(cid: str, body: ImportRequest) -> list[TargetOut]:
    try:
        return await app.state.service.import_targets(
            cid, body.venue_id, body.serials, body.ssh_password)
    except KeyError:
        raise HTTPException(404, "unknown controller")
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(502, f"controller API error: {e}")


# -- inventory: targets (capture APs) -----------------------------------------
@app.get("/api/targets", response_model=list[TargetOut])
async def list_targets() -> list[TargetOut]:
    return await app.state.service.list_targets()


@app.post("/api/targets", response_model=TargetOut)
async def create_target(spec: TargetCreate) -> TargetOut:
    return await app.state.service.create_target(spec)


@app.put("/api/targets/{tid}", response_model=TargetOut)
async def update_target(tid: str, patch: TargetUpdate) -> TargetOut:
    try:
        return await app.state.service.update_target(
            tid, patch.model_dump(exclude_unset=True))
    except KeyError:
        raise HTTPException(404, "unknown target")
    except ValueError as e:
        raise HTTPException(422, str(e))


@app.delete("/api/targets/{tid}")
async def delete_target(tid: str) -> JSONResponse:
    await app.state.service.delete_target(tid)
    return JSONResponse({"deleted": tid})


# -- sessions -----------------------------------------------------------------
@app.post("/api/sessions", response_model=SessionOut)
async def create_session(spec: SessionCreate) -> SessionOut:
    sid = await app.state.service.create_session(spec)
    return await app.state.service.get_session(sid)


@app.get("/api/sessions", response_model=list[SessionOut])
async def list_sessions() -> list[SessionOut]:
    return await app.state.service.list_sessions()


@app.get("/api/sessions/{sid}", response_model=SessionOut)
async def get_session(sid: str) -> SessionOut:
    out = await app.state.service.get_session(sid)
    if not out:
        raise HTTPException(404, "unknown session")
    return out


@app.delete("/api/sessions/{sid}")
async def delete_session(sid: str) -> JSONResponse:
    removed = await app.state.service.delete_session(sid)
    return JSONResponse({"deleted": sid, "files_removed": removed})


@app.post("/api/maintenance/purge-completed")
async def purge_completed() -> JSONResponse:
    return JSONResponse(await app.state.service.purge_completed())


@app.get("/api/maintenance/disk-usage")
async def disk_usage() -> JSONResponse:
    return JSONResponse(app.state.service.disk_usage())


@app.post("/api/sessions/{sid}/assignments", response_model=SessionOut)
async def add_assignment(sid: str, spec: AssignmentCreate) -> SessionOut:
    try:
        await app.state.service.add_assignment(sid, spec)
    except KeyError:
        raise HTTPException(404, "unknown session")
    except ValueError as e:
        raise HTTPException(409, str(e))
    return await app.state.service.get_session(sid)


@app.delete("/api/sessions/{sid}/assignments/{aid}", response_model=SessionOut)
async def delete_assignment(sid: str, aid: str) -> SessionOut:
    try:
        await app.state.service.delete_assignment(sid, aid)
    except ValueError as e:
        raise HTTPException(409, str(e))
    return await app.state.service.get_session(sid)


@app.post("/api/sessions/{sid}/start", response_model=SessionOut)
async def start_session(sid: str, body: SessionStart) -> SessionOut:
    # Creds resolve per-assignment (target -> controller -> CT_AP_PASSWORD fallback);
    # an assignment with no resolvable password just fails at login with a clear error.
    try:
        await app.state.service.start_session(sid, body.duration_s)
    except KeyError:
        raise HTTPException(404, "unknown session")
    except ValueError as e:
        raise HTTPException(409, str(e))
    return await app.state.service.get_session(sid)


@app.post("/api/sessions/{sid}/stop", response_model=SessionOut)
async def stop_session(sid: str) -> SessionOut:
    try:
        await app.state.service.stop_session(sid)
    except KeyError:
        raise HTTPException(404, "unknown session")
    except ValueError as e:
        raise HTTPException(409, str(e))
    return await app.state.service.get_session(sid)


@app.post("/api/sessions/{sid}/assignments/{aid}/arm", response_model=SessionOut)
async def arm_assignment(sid: str, aid: str) -> SessionOut:
    # stream_wireshark holds in `awaiting_wireshark` until the analyst has Wireshark
    # pointed at the rpcap URL; arming starts the timed capture window.
    if not app.state.engine.arm(aid):
        raise HTTPException(409, "assignment is not awaiting Wireshark setup")
    out = await app.state.service.get_session(sid)
    if not out:
        raise HTTPException(404, "unknown session")
    return out


@app.get("/api/sessions/{sid}/events")
async def session_events(sid: str) -> StreamingResponse:
    if not await app.state.service.get_session(sid):
        raise HTTPException(404, "unknown session")

    async def gen():
        terminal = {"done", "failed"}
        while True:
            out = await app.state.service.get_session(sid)
            if out is None:
                break
            yield f"data: {out.model_dump_json()}\n\n"
            if out.status in terminal:
                break
            await asyncio.sleep(1.0)

    return StreamingResponse(gen(), media_type="text/event-stream")


@app.post("/api/sessions/{sid}/merge", response_model=ArtifactOut)
async def merge_session(sid: str, body: MergeRequest) -> ArtifactOut:
    try:
        return await app.state.service.merge_session(sid, body.assignment_ids)
    except KeyError:
        raise HTTPException(404, "unknown session")
    except ValueError as e:
        raise HTTPException(409, str(e))
    except Exception as e:  # merge tooling failure
        raise HTTPException(500, f"merge failed: {e}")


# -- templates ----------------------------------------------------------------
@app.get("/api/templates", response_model=list[TemplateOut])
async def list_templates() -> list[TemplateOut]:
    return await app.state.service.list_templates()


@app.post("/api/templates", response_model=TemplateOut)
async def create_template(spec: TemplateCreate) -> TemplateOut:
    return await app.state.service.create_template(spec)


@app.post("/api/sessions/{sid}/save-template", response_model=TemplateOut)
async def save_template_from_session(sid: str, body: SaveTemplate) -> TemplateOut:
    try:
        return await app.state.service.save_template_from_session(
            sid, body.name, body.description)
    except KeyError:
        raise HTTPException(404, "unknown session")
    except ValueError as e:
        raise HTTPException(409, str(e))


@app.post("/api/templates/{tid}/instantiate", response_model=SessionOut)
async def instantiate_template(tid: str, body: Instantiate) -> SessionOut:
    try:
        sid = await app.state.service.instantiate_template(tid, body.name)
    except KeyError:
        raise HTTPException(404, "unknown template")
    return await app.state.service.get_session(sid)


@app.delete("/api/templates/{tid}")
async def delete_template(tid: str) -> JSONResponse:
    await app.state.service.delete_template(tid)
    return JSONResponse({"deleted": tid})


# -- artifacts ----------------------------------------------------------------
@app.get("/api/artifacts/{art_id}/download")
async def download_artifact(art_id: str) -> FileResponse:
    path = await app.state.service.artifact_file(art_id)
    if not path:
        raise HTTPException(404, "no artifact file")
    media = ("application/x-pcapng" if path.suffix == ".pcapng"
             else "application/vnd.tcpdump.pcap")
    return FileResponse(path, media_type=media, filename=path.name)


@app.get("/api/assignments/{aid}/download")
async def download_assignment(aid: str) -> FileResponse:
    res = await app.state.service.assignment_file(aid)
    if not res:
        raise HTTPException(404, "no capture file")
    path, _sidecar = res
    return FileResponse(path, media_type="application/vnd.tcpdump.pcap",
                        filename=f"{aid}.pcap")


@app.get("/api/assignments/{aid}/sidecar")
async def sidecar_assignment(aid: str) -> dict:
    res = await app.state.service.assignment_file(aid)
    if not res or res[1] is None:
        raise HTTPException(404, "no sidecar")
    return res[1]


# -- ad-hoc single capture (engine-direct, not persisted as a session) --------
@app.post("/api/captures", response_model=CaptureStatus)
async def create_capture(spec: CaptureSpec) -> CaptureStatus:
    if not app.state.settings.ap_password:
        raise HTTPException(400, "CT_AP_PASSWORD not set on the server")
    return app.state.engine.start(spec).status()


@app.get("/api/captures", response_model=list[CaptureStatus])
async def list_captures() -> list[CaptureStatus]:
    return [j.status() for j in app.state.engine.list_jobs()]
