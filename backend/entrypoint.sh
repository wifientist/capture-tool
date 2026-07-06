#!/bin/sh
set -e

# Wait for the database, then apply migrations before serving.
echo "[entrypoint] applying migrations..."
for i in $(seq 1 30); do
  if alembic upgrade head; then
    break
  fi
  echo "[entrypoint] db not ready yet ($i)…"; sleep 2
done

echo "[entrypoint] starting uvicorn on :8000"
exec uvicorn app.main:app --host 0.0.0.0 --port 8000
