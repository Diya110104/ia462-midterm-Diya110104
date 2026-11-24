#!/usr/bin/env bash
# Re-derive the seccomp allow-list on your own Linux/WSL host.
# Runs the app under gunicorn with strace, exercises every route, then rebuilds
# section3/seccomp-profile.json.  Requires: python3, strace, curl.
# Usage (from midterm/):  ./scripts/trace-syscalls.sh
set -euo pipefail
cd "$(dirname "$0")/.."

python3 -m venv /tmp/ia462-trace-venv
/tmp/ia462-trace-venv/bin/pip install -q --require-hashes -r requirements.lock

export PYTHONDONTWRITEBYTECODE=1
( cd app && strace -f -qq -o /tmp/ia462-strace.log \
    /tmp/ia462-trace-venv/bin/gunicorn --bind 127.0.0.1:8099 --workers 2 --threads 2 \
    --worker-tmp-dir /tmp app:app ) &
sleep 4
for u in / /health /whoami /api/items /api/items/1 /does-not-exist; do
  curl -s -o /dev/null -w "%{http_code} $u\n" "http://127.0.0.1:8099$u"
done
curl -s -X POST -H 'Content-Type: application/json' -d '{"name":"trace"}' http://127.0.0.1:8099/api/items; echo
# HEALTHCHECK command
strace -f -qq -o /tmp/ia462-strace-hc.log /tmp/ia462-trace-venv/bin/python -c \
  "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8099/health', timeout=2)"
pkill -TERM -f 'gunicorn --bind 127.0.0.1:8099' || true
sleep 2

awk '{print $2}' /tmp/ia462-strace.log /tmp/ia462-strace-hc.log \
  | grep -oE '^[a-z0-9_]+\(' | tr -d '(' | sort -u > section3/seccomp-traced-syscalls.txt
echo "traced $(wc -l < section3/seccomp-traced-syscalls.txt) distinct syscalls"
python3 scripts/seccomp-from-strace.py section3/seccomp-traced-syscalls.txt section3/seccomp-profile.json
