#!/bin/bash
# Native Go fixtures need package-private helpers; keep the focused public
# extraction entry point in ci/. Docker's testscope lane also discovers them.
set -eu
go test -race ./internal/extract -run '^(TestExtractRC4MD5WorkbookFixture|TestExtractEncryptedOOXMLFixture|TestRC4MD5|TestXLMBIFF|TestEncType)' "$@"
