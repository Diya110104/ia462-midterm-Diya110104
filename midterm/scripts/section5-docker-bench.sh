#!/usr/bin/env bash
# IA 462 midterm - Section 5: CIS Docker Benchmark via docker-bench-security.
# Run on the Linux host that runs dockerd (an Ubuntu VM, or WSL with Docker Engine
# installed inside WSL. Docker Desktop's VM hides most host checks).
# Start the hardened container first so the runtime checks (section 5) have a target:
#   ./section3/run-command.sh
# Usage (from midterm/):  sudo ./scripts/section5-docker-bench.sh
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="$PWD/section5"
# Pinned to a commit, not a branch, like every other third-party dependency here.
BENCH_COMMIT="154869da6418089decf7e1ab0cfca0e1cdfc5c49"
DIR=/tmp/docker-bench-security

if [ ! -d "$DIR/.git" ]; then git clone -q https://github.com/docker/docker-bench-security.git "$DIR"; fi
git -C "$DIR" fetch -q origin && git -C "$DIR" checkout -q "$BENCH_COMMIT"
echo "docker-bench-security @ $(git -C "$DIR" rev-parse HEAD)"

cd "$DIR"
sh docker-bench-security.sh -b 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | tee "$OUT/docker-bench-report.txt"
echo
grep -E '^\[(WARN|PASS|INFO|NOTE)\]' "$OUT/docker-bench-report.txt" | cut -d' ' -f1 | sort | uniq -c
grep -E 'Score|Checks' "$OUT/docker-bench-report.txt" | tail -3
echo ">> Screenshot: section5/screenshots/19-docker-bench.png"
