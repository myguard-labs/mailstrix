#!/bin/sh
# Build exactly the production static YARA stage, then exercise its real reads.
# The original compiler/archive retained by that stage are independent oracles.
set -eu
for executable in docker python3; do
	command -v "$executable" >/dev/null 2>&1 || {
		echo "native compiler proof: required executable unavailable: $executable" >&2
		exit 1
	}
done
docker info >/dev/null 2>&1 || {
	echo "native compiler proof: Docker daemon unavailable; check runner daemon and permissions" >&2
	exit 1
}
if [ "${1-}" = --prerequisites-only ]; then
	exit 0
fi
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
# Public archive key from ci/goldenimage/deb.myguard.nl.gpg in the MyGuard
# superrepo, SHA-256 verified against the host public key. Bootstrap only the
# disposable context; runners need no preinstalled key or host-state writes.
python3 - "$scratch" <<'KEY'
import base64
import binascii
import hashlib
import sys
from pathlib import Path

encoded = """
mQINBF/ospwBEAC+F74LLkDiClZl43NKWHPEXLb0oSisG52wxVuby+n44QmBi4vlcYdBbLwOsHH7
YA1qEN5bSwF1oNHV6jC4bJoFhWMOXZ3jojn2SZ6AcMzORBVTvQWQNO+sVEZR5L4He57DrRjNns11
WCpRw/BHknhqfRb7Wt/EqPiSvhKuiBQDM+Pj9IE1tzqfyKmE2OgJwWyNvvDf2mJLQvyLeKt+dyEo
bat4125TGFeOSNM8oVxPCyNsVJQNUM9G9FymALZ/b0sLg5YRSGyXKeNVOya0lnPzP5hnUa0rPP0F
XJdRk+hChnCBRoe+E+hWcY5AflLjAmLLzOmv/4F2ObSChdCgGzZ1AXkyZxLVqhUMgvpUCnD9qM5c
yeHS2qsJVgJYrVhr15QfRKLcXhtC5KAMjro2ZMRPzH/ftMjb6dKAtID6fX4gVq4DlaL0lEcLIHXS
Tq4IlIN6do5RpWSMnjxca3wsG6LEuQ6BBscbQ3kjEWW6vnojZK6ITIQpa4QO625hZiczQNzJF5of
IPmmJ6/SjU+mZn4KG7MaQ2a+mGK4B11Vjo8UVWQUiYSCAv1fVQl8sljU2BjIa/zvd+YNNz6Q0uEl
mu9yNc50iI8qJO6ESOqGwYF0RfZc+sStm8+GTRqmTf3OqfS396CrtMS190z0TCnbXigRQA+Klvp7
sLhIwDyXu8CJRwARAQABtCRUaGlqcyBFaWxhbmRlciA8ZWlsYW5kZXJAbXlndWFyZC5ubD6JAlUE
EwEIAD8CGwMGCwkIBwMCBhUIAgkKCwQWAgMBAh4BAheAFiEE0YuOWt99Vc4qANWBZ/nD2EVtf2IF
AmoYcD8FCQ3yJKMACgkQZ/nD2EVtf2Kayg//f1T825FsMH2xTKlJNESJLdBGm8n2FhHyDIJiNjvV
0OdSshLBSXNl1ioTOwsw1M+huiJvHt5ZAxd2AFi2y+fgbEjCrEJGP09SOuaVa4T2bBI2BZUr4T2b
aB6+by+4fueXKxsWvsyWr+Gr5okCwk0/AsqMO0NKyJXhq0CeXRupjadev3mx3IwJoX/Lh8E4dnmo
Eq2CACjnyC7KC6JUCDxYmSot9L02EK7mbDvcRn1aGXG4NQdJe9b8un1kUjawdwnyKhsMrkUt+TQN
96j4Ct8qNql3HXQfIlJWikdSfCDavHtltAZeQManbuhdQhzs5WWAD4Bfy+O7XYflB/a6MVKfJQ/V
r+9holyEZz1gKM8rEc88LtwBOHo29DIwYDECxwWDbgFE0nJaBqehcEXQOHHB/lkhk1Lotf78y0RD
CxzxbmxHDRnZ2cCQ1qKVNAxGpZGCCJJCVybpIFi+JPe632QuRDnbwSAFswm9pfg2QgbFDZmw6gkX
im6Q21tg9dXdw70mVbMcQwtArmYJ9jkB6e+9E4ukwime45OVAIFohxttVKtSiwvZVVWoB/KvdGAM
HCTPsRJgu/kzNMvprnh6d1LkCLVWmtZN4eAVcsfSLHMH81PqzDLGb86RE/GsyoWoRWHFkxc3NWkZ
1jYQK+yQrhSgA6fsQT36Vvvnrg//W8emmx4=
"""
try:
    public_key = base64.b64decode("".join(encoded.split()), validate=True)
except binascii.Error as error:
    raise SystemExit("native compiler proof: malformed pinned public archive key") from error
if hashlib.sha256(public_key).hexdigest() != "9744a10c48237234dcb762b5f7326ed21b6944a6f079cc3624169edf90118bdc":
    raise SystemExit("native compiler proof: pinned public archive key checksum mismatch")
try:
    (Path(sys.argv[1]) / "deb.myguard.nl.gpg").write_bytes(public_key)
except OSError as error:
    raise SystemExit("native compiler proof: cannot provision disposable public archive key") from error
KEY
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
