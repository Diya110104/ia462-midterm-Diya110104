#!/usr/bin/env bash
# IA 462 midterm - Section 4: Trivy + Syft + Grype against the hardened image.
# Usage (from midterm/):  docker build -t ia462-midterm:hardened . && ./scripts/section4-scan.sh
#
# Scanner versions are pinned. Trivy 0.69.4-0.69.6 were MALICIOUS releases
# (GHSA-69fq-xp46-6x23, March 2026): never use :latest for scanners.
# The digest of each scanner image is written into the report header, so the
# exact bits that ran are recorded.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="$PWD/section4"
IMAGE="${IMAGE:-ia462-midterm:hardened}"
TRIVY_IMG="ghcr.io/aquasecurity/trivy:0.76.2"
SYFT_IMG="ghcr.io/anchore/syft:v1.57.2"
GRYPE_IMG="ghcr.io/anchore/grype:v0.122.1"

for i in "$TRIVY_IMG" "$SYFT_IMG" "$GRYPE_IMG"; do docker pull -q "$i" >/dev/null; done
digest() { docker image inspect --format '{{index .RepoDigests 0}}' "$1"; }
SOCK=(-v /var/run/docker.sock:/var/run/docker.sock:ro)
CACHE=(-v ia462-scan-cache:/root/.cache)

echo "== Trivy (CRITICAL,HIGH,MEDIUM)"
{
  echo "# trivy image --severity CRITICAL,HIGH,MEDIUM $IMAGE"
  echo "# scanner: $(digest "$TRIVY_IMG")  |  image: $(docker image inspect --format '{{.Id}}' "$IMAGE")  |  $(date -u +%FT%TZ)"
  docker run --rm "${SOCK[@]}" "${CACHE[@]}" "$TRIVY_IMG" image --scanners vuln \
    --severity CRITICAL,HIGH,MEDIUM --format table "$IMAGE"
} | tee "$OUT/trivy-report.txt"
echo ">> Screenshot: section4/screenshots/14-trivy.png"

echo "== Syft SBOM (SPDX JSON)"
docker run --rm "${SOCK[@]}" "$SYFT_IMG" "docker:$IMAGE" -o spdx-json > "$OUT/sbom.spdx.json"
docker run --rm "${SOCK[@]}" "$SYFT_IMG" "docker:$IMAGE" -o table | head -40
echo "SBOM packages: $(python3 -c "import json;print(len(json.load(open('$OUT/sbom.spdx.json'))['packages']))")"
echo ">> Screenshot: section4/screenshots/15-syft.png"

echo "== Grype against the SBOM"
{
  echo "# grype sbom:sbom.spdx.json"
  echo "# scanner: $(digest "$GRYPE_IMG")  |  $(date -u +%FT%TZ)"
  docker run --rm -v "$OUT:/in:ro" -v ia462-grype-db:/root/.cache "$GRYPE_IMG" sbom:/in/sbom.spdx.json -o table
} | tee "$OUT/grype-report.txt"
echo ">> Screenshot: section4/screenshots/16-grype.png"

echo
echo "CRITICAL/HIGH candidates for cve-writeup.md:"
grep -hoE 'CVE-[0-9]{4}-[0-9]+' "$OUT/trivy-report.txt" "$OUT/grype-report.txt" | sort | uniq -c | sort -rn | head -15
grep -E 'CRITICAL|HIGH' "$OUT/trivy-report.txt" | head -15 || echo "(no CRITICAL/HIGH in Trivy - check grype-report.txt, or see cve-writeup.md for what to do)"
