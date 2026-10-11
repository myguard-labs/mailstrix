#!/bin/sh
# Build exactly the production static YARA stage, then exercise its real reads.
# The original compiler/archive retained by that stage are independent oracles.
set -eu
repo="$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)"
scratch="$(mktemp -d /tmp/mailstrix-input-check.XXXXXXXX)"
image="mailstrix-input-check:$(basename "$scratch")"
container="$(basename "$scratch")"
cleanup() {
	docker container rm -f "$container" >/dev/null 2>&1 || :
	docker image rm "$image" >/dev/null 2>&1 || :
	rm -rf "${scratch:?}"
}
trap cleanup EXIT HUP INT TERM
# Signed APT source is required for disposable MyGuard containers. Keep the
# keyring out of the project tree and the production build context.
cp /etc/apt/keyrings/deb.myguard.nl.gpg "$scratch/deb.myguard.nl.gpg"
cp "$repo/docker/compiler-input-capture.h" "$repo/docker/patch-compiler-input-capture.py" "$scratch/"
python3 - "$repo" "$scratch" <<'PY'
from pathlib import Path
import sys
repo, scratch = map(Path, sys.argv[1:])
source = (repo / 'docker/Dockerfile').read_text()
marker = '# ---- go build'
if source.count(marker) != 1:
    raise SystemExit('production yara-stage boundary changed')
source = source.split(marker)[0]
if source.count('RUN apt-get update') != 1:
    raise SystemExit('production yara-stage apt prerequisite changed')
source = source.replace('RUN apt-get update', '''COPY deb.myguard.nl.gpg /etc/apt/keyrings/deb.myguard.nl.gpg
RUN echo "deb [signed-by=/etc/apt/keyrings/deb.myguard.nl.gpg] http://deb.myguard.nl:8888 bookworm main" > /etc/apt/sources.list.d/deb.myguard.nl.list
RUN apt-get update''')
source = source.replace('COPY docker/compiler-input-capture.h docker/patch-compiler-input-capture.py',
                        'COPY compiler-input-capture.h patch-compiler-input-capture.py')
(scratch / 'Dockerfile').write_text(source)
PY
docker build --progress=plain -t "$image" "$scratch"
docker run --rm --name "$container" -v "$repo:/repo:ro" "$image" \
	sh -c 'cd /repo && python3 -B ci/compiler_input_retention_test.py -v'
