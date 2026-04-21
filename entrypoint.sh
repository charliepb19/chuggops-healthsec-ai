#!/bin/sh
# entrypoint.sh — waits for the database then starts the app
set -e

echo "==> ChuggOps HealthSec AI starting..."

# If DATABASE_URL points at PostgreSQL, wait until it accepts connections
if echo "${DATABASE_URL:-}" | grep -q "postgresql"; then
    echo "==> Waiting for PostgreSQL at $DATABASE_URL ..."
    until python - <<'EOF'
import os, sys
try:
    import sqlalchemy
    engine = sqlalchemy.create_engine(os.environ["DATABASE_URL"])
    with engine.connect():
        pass
    print("==> Database is ready.")
except Exception as e:
    print(f"    Not ready: {e}", file=sys.stderr)
    sys.exit(1)
EOF
    do
        echo "    Retrying in 2s..."
        sleep 2
    done
fi

# Determine worker count: 2 workers is safe for most hospital-grade VMs.
# Override with WORKERS env var if you have more CPU.
WORKERS="${WORKERS:-2}"

echo "==> Starting uvicorn with $WORKERS worker(s)..."
exec uvicorn app.main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --workers "$WORKERS" \
    --access-log \
    --log-level info \
    --proxy-headers \
    --forwarded-allow-ips "*"
