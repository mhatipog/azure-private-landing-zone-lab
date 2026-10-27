#!/usr/bin/env bash
# Read-only postdeployment observation. Run on a trusted, authenticated CI agent.
set -euo pipefail
: "${LOG_ANALYTICS_WORKSPACE_ID:?Set the Log Analytics workspace GUID}"
: "${MONITOR_SPEC:?Path to reviewed monitor specification JSON}"
mkdir -p evidence
az monitor log-analytics query \
  --workspace "$LOG_ANALYTICS_WORKSPACE_ID" \
  --analytics-query "$(cat queries/connection-monitor.kql)" \
  --timespan PT30M -o json > evidence/connection-monitor-rows.json
az-private-ready monitor-gate evidence/connection-monitor-rows.json "$MONITOR_SPEC" \
  --output evidence/connection-monitor-verdict.json
