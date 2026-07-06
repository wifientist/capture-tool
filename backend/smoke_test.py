import asyncio, time
from app.config import Settings
from app.engine.orchestrator import Engine
from app.models import CaptureSpec

async def main():
    s = Settings()  # CT_AP_PASSWORD from env
    eng = Engine(s)
    job = eng.start(CaptureSpec(ap_host="10.0.71.128", iface="wifi0",
                                duration_s=6, name="smoke"))
    print("started", job.id)
    for _ in range(12):
        await asyncio.sleep(1)
        st = job.status()
        print(f"  state={st.state.value:11} frames={st.frames:4} bytes={st.bytes:6} "
              f"chan={st.channel} linktype={st.linktype} err={st.error}")
        if st.state in ("done", "failed"):
            break
    await eng.shutdown()
    print("file:", job.file_path, job.file_path.exists(), job.file_path.stat().st_size, "bytes")

asyncio.run(main())
