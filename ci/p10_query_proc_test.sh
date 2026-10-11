#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
go test -count=1 -run '^TestP10(MaintenanceInitialQueryFailure|MaintenanceQuerySuccess|SchedulerWrapQueryFailure|ProcStatReadDisappearance)$' ./internal/cape ./tools/parity
