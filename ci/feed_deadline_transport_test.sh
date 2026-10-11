#!/bin/bash
# Package-private deadline fixture regression; full Go CI also discovers it.
set -euo pipefail
cd "$(dirname "$0")/.."
go test -race -p 1 -count=1 -timeout=30m -run '^TestScanReputationDeadlineForwarding' ./internal/mailstrix
