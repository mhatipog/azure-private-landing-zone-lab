#!/usr/bin/env bash
set -euo pipefail
python -m pip install -e .
az-private-ready topology examples/topology.json
az-private-ready assess tests/fixtures/compliant.json --format json --output /tmp/az-ready-pass.json
if az-private-ready assess tests/fixtures/broken.json --format markdown --output /tmp/az-ready-fail.md; then
  echo "Unexpected green status for broken evidence" >&2; exit 1
fi
echo "Demo reports: /tmp/az-ready-pass.json and /tmp/az-ready-fail.md"
