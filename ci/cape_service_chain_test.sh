#!/bin/bash
# Focused real TLS/API/Store/Scheduler regression entry point. The regular
# native Go lane also discovers these tests in internal/mailstrix.
set -euo pipefail
cd "$(dirname "$0")/.."
go test -race -tags yara_static -count=1 -run '^TestCAPEServiceChain' \
	./internal/mailstrix "$@"
