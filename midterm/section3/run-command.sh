#!/usr/bin/env bash
# IA 462 midterm - exact hardened `docker run` invocation (Section 3).
# Usage (from anywhere):  ./midterm/section3/run-command.sh
# Then: curl http://127.0.0.1:8000/whoami
#       docker exec ia462-hardened id          # expect uid=10001(appuser)
#       docker exec ia462-hardened whoami      # expect appuser
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="${IMAGE:-ia462-midterm:hardened}"

docker rm -f ia462-hardened >/dev/null 2>&1 || true

docker run -d \
  --name ia462-hardened \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --security-opt seccomp="${HERE}/seccomp-profile.json" \
  --user 10001:10001 \
  --pids-limit 100 \
  --memory 256m \
  --cpus 0.5 \
  --restart on-failure:3 \
  -p 127.0.0.1:8000:8000 \
  "${IMAGE}"

sleep 3
echo "--- container user ---"
docker exec ia462-hardened id
docker exec ia462-hardened whoami
echo "--- security settings as seen by Docker ---"
docker inspect ia462-hardened --format \
  'ReadOnly={{.HostConfig.ReadonlyRootfs}} CapDrop={{.HostConfig.CapDrop}} User={{.Config.User}}'
docker inspect ia462-hardened --format '{{json .HostConfig.SecurityOpt}}' | cut -c1-90; echo " ...(seccomp JSON truncated)"
echo "--- seccomp is active (Seccomp: 2 = filter mode) ---"
docker exec ia462-hardened grep -E 'Seccomp|NoNewPrivs|CapEff' /proc/1/status
echo "--- read-only root fs check (should fail) ---"
docker exec ia462-hardened sh -c 'touch /app/pwned' || echo "write blocked: OK"
echo "--- app response ---"
curl -s http://127.0.0.1:8000/whoami; echo
