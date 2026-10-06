#!/usr/bin/env bash
# Run an OWASP ZAP baseline scan against a Juice Shop instance you own.
# Requires Docker. Produces a timestamped HTML report.
#
# Usage: ./zap_scan.sh http://10.20.1.10:3000 /var/log/zap-reports

set -euo pipefail

TARGET="${1:-http://10.20.1.10:3000}"
OUT_DIR="${2:-/var/log/zap-reports}"
TS="$(date +%Y%m%d_%H%M%S)"

mkdir -p "$OUT_DIR"

docker run --rm \
  -v "$OUT_DIR:/zap/wrk/:rw" \
  -t zaproxy/zap-stable \
  zap-baseline.py \
  -t "$TARGET" \
  -r "report_${TS}.html" \
  -I

echo "Report saved to $OUT_DIR/report_${TS}.html"
