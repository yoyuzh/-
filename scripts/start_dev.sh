#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

BACKEND_HOST="${BACKEND_HOST:-127.0.0.1}"
BACKEND_PORT="${BACKEND_PORT:-8000}"
FRONTEND_HOST="${FRONTEND_HOST:-127.0.0.1}"
FRONTEND_PORT="${FRONTEND_PORT:-3000}"

BACKEND_PID=""
FRONTEND_PID=""

cleanup() {
  if [[ -n "${FRONTEND_PID}" ]] && kill -0 "${FRONTEND_PID}" 2>/dev/null; then
    kill "${FRONTEND_PID}" 2>/dev/null || true
  fi
  if [[ -n "${BACKEND_PID}" ]] && kill -0 "${BACKEND_PID}" 2>/dev/null; then
    kill "${BACKEND_PID}" 2>/dev/null || true
  fi
}

trap cleanup EXIT INT TERM

cd "${REPO_ROOT}"

if [[ ! -d "web/node_modules" ]]; then
  echo "Installing frontend dependencies..."
  (cd web && npm install)
fi

echo "Starting backend on http://${BACKEND_HOST}:${BACKEND_PORT}"
python3 start.py --host "${BACKEND_HOST}" --port "${BACKEND_PORT}" --strict-port &
BACKEND_PID="$!"

echo "Starting frontend on http://${FRONTEND_HOST}:${FRONTEND_PORT}/static/"
(cd web && npm run dev -- --host "${FRONTEND_HOST}" --port "${FRONTEND_PORT}") &
FRONTEND_PID="$!"

cat <<EOF

Development services are starting:
- Backend API: http://${BACKEND_HOST}:${BACKEND_PORT}
- Frontend UI: http://${FRONTEND_HOST}:${FRONTEND_PORT}/static/

Press Ctrl+C to stop both services.
EOF

wait -n "${BACKEND_PID}" "${FRONTEND_PID}"
