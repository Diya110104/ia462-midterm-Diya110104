#!/usr/bin/env bash
# The assignment wants copies of some files inside section folders.
# Edit the originals, then run this (from the repo root or anywhere).
#   --check : exit non-zero if any copy differs (used by CI)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
pairs=(
  "midterm/Dockerfile:midterm/section3/Dockerfile"
  "midterm/requirements.txt:midterm/section6/requirements.txt"
  "midterm/requirements.lock:midterm/section6/requirements.lock"
  ".github/dependabot.yml:midterm/section6/dependabot.yml"
  ".github/workflows/security-pipeline.yml:midterm/section6/security-pipeline.yml"
  ".github/workflows/dependency-review.yml:midterm/section6/dependency-review.yml"
)
rc=0
for p in "${pairs[@]}"; do
  src="$ROOT/${p%%:*}"; dst="$ROOT/${p##*:}"
  if [[ "${1:-}" == "--check" ]]; then
    if ! cmp -s "$src" "$dst"; then echo "OUT OF SYNC: ${p##*:} (run scripts/sync-copies.sh)"; rc=1; fi
  else
    cp "$src" "$dst"; echo "copied ${p%%:*} -> ${p##*:}"
  fi
done
exit $rc
