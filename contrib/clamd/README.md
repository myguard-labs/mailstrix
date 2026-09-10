# clamd stream adapter

[Mailstrix](../../README.md) can serve a small clamd-compatible stream protocol
inside the existing `strixd serve` process. It uses the same scan engine and
actionable/log-only distinction as the other adapters. Both listeners are
disabled unless configured. This is a supported subset, not ClamAV emulation:
Mailstrix rules and detection results do not become ClamAV signatures.

## Enable a listener

| Environment variable | Default | Meaning |
| --- | --- | --- |
| `MAILSTRIX_CLAMD_UNIX_PATH` | empty | Absolute socket path |
| `MAILSTRIX_CLAMD_TCP_ADDR` | empty | Explicit `host:port` |
| `MAILSTRIX_CLAMD_MAX_CONNS` | `64` | Shared cap, range 1–1024 |

The Unix socket's parent directory must exist. An example TCP address is
`127.0.0.1:3310`.
Invalid connection caps fall back to 64. The payload cap is the existing
`MAILSTRIX_MAX_BODY` (8 MiB by default), with a 1 GiB hard ceiling.
HTTP and ICAP configuration retain their existing behavior.

Unix sockets use mode `0600`. Run a Unix client as the `strixd` user (or another
identity permitted to access that socket); arbitrary group access is not enabled.
The parent directory must be controlled by the operator. Startup publishes an
already private socket with a filesystem hard link, failing if the requested
path exists. Filesystems must support hard links to Unix sockets. Automatic
stale-socket replacement is not supported; inspect any existing socket before
removing it. Normal shutdown removes only the socket created by this listener.
On Linux, near-limit Unix socket paths require an accessible /proc/self/fd
directory for private staging; startup fails without publishing a socket if
that fallback is unavailable.

TCP has no protocol authentication or TLS. `MAILSTRIX_TOKEN` protects the HTTP
API, not clamd. Keep TCP on a trusted host/network; do not expose port 3310 to
untrusted clients. Explicitly configuring a wildcard address enables that bind;
there is no implicit public listener.

### systemd example

For the packaged service, an optional drop-in at
`/etc/systemd/system/strixd.service.d/clamd.conf` can use its existing runtime
directory:

```ini
[Service]
Environment=MAILSTRIX_CLAMD_UNIX_PATH=/run/strixd/clamd.sock
Environment=MAILSTRIX_CLAMD_MAX_CONNS=64
```

Alternatively set `MAILSTRIX_CLAMD_TCP_ADDR=127.0.0.1:3310` in the service's
environment file for a trusted local mail filter using a different Unix UID.
These examples require operator installation and service restart; they do not
change the shipped service defaults.

### Docker example

This explicitly binds the container listener and publishes it only on the
host's loopback interface. Use a trusted container network as well: peers on
that network can reach the container's port directly.

```sh
docker run --rm --name mailstrix-clamd \
  -e MAILSTRIX_HOST=127.0.0.1 \
  -e MAILSTRIX_CLAMD_TCP_ADDR=0.0.0.0:3310 \
  -p 127.0.0.1:3310:3310 \
  myguard-labs/mailstrix
```

Use a build/release containing this adapter. This command does not publish the
HTTP port; it leaves the image's existing baked-rule configuration in place.

## Client and mail-filter examples

For `clamdscan`, use a client configuration file:

```text
TCPAddr 127.0.0.1
TCPSocket 3310
```

For Unix transport replace those two lines with
`LocalSocket /run/strixd/clamd.sock`, and run the client with socket access.
Submit file bytes with `--stream`, without `--multiscan` or `--fdpass`:

```sh
clamdscan --config-file=/etc/mailstrix/clamd-client.conf --stream attachment.bin
```

For an existing Python mail filter using `clamd==1.0.2`, its attachment-buffer
hook can use:

```python
import io
import clamd

client = clamd.ClamdNetworkSocket(host="127.0.0.1", port=3310, timeout=60)
result = client.instream(io.BytesIO(attachment_bytes))
status, reason = result["stream"]
if status == "FOUND":
    quarantine_attachment(reason)
elif status == "ERROR":
    defer_delivery(reason)
else:
    continue_delivery()
```

The three delivery functions above stand for the filter's existing policy
hooks. Handle connection/size exceptions through that filter's error policy,
too; transport failure is never a clean scan. The 60-second client budget must
also fit the enclosing MTA/filter timeout. Submit an attachment's bytes, not
a daemon-visible path. This adapter cannot accept filename or extension
metadata. Mailstrix's own [Milter](../postfix/) and [Sieve](../sieve/) adapters
remain options where the existing mail stack lacks a stream-client hook.

## Protocol and limits

The [official clamd protocol](https://docs.clamav.net/manual/Usage/ClamdProtocol.html)
defines the framing and stream records used here. Send either `zCOMMAND\0`
(NUL terminator) or `nCOMMAND\n` (LF terminator); replies use the same terminator.
Commands are exact uppercase tokens without arguments. CRLF, control characters,
unprefixed legacy commands and commands beyond 64 framed bytes are rejected.

| Command/result | Reply payload (before the terminator) |
| --- | --- |
| `PING` | `PONG` |
| `VERSION` | `Mailstrix <version>` |
| `VERSIONCOMMANDS` | Version and command list, shown below |
| Successful clean or log-only stream | `stream: OK` |
| Actionable match | `stream: Mailstrix.Match FOUND` |
| Scanner error/panic | `stream: scan failed ERROR` |
| Total size exceeded | `INSTREAM size limit exceeded. ERROR` |
| Chunk size exceeded | `stream: chunk size limit exceeded ERROR` |
| Queue budget exhausted | `stream: busy ERROR` |
| Scan response deadline | `stream: scan timed out ERROR` |
| Unsupported command | `UNKNOWN COMMAND` |

The `VERSIONCOMMANDS` reply is exactly
`Mailstrix <version> COMMANDS: PING VERSION VERSIONCOMMANDS INSTREAM`.

INSTREAM data follows the command on the same connection: unsigned four-byte
big-endian length, then that many bytes, repeated until a zero length. Individual
chunks cannot exceed 1 MiB or the remaining total quota. Empty streams are valid.
Truncated streams never reach the engine. The server does not drain a rejected
upload, so a client still sending bytes may receive a transport exception instead
of the textual error. Reconnect for every command/stream; pipelined trailing
bytes are discarded and never become a second scan.

| Budget | Limit |
| --- | --- |
| Command read | Absolute 5 seconds from accept |
| Body read | Absolute 30 seconds from command completion |
| Admission/CPU queue wait | `MAILSTRIX_BACKEND_TIMEOUT`, default 1 second |
| Scan response | `MAILSTRIX_SCAN_TIMEOUT` plus 2 seconds; default 10 seconds |
| Reply write | Absolute 1 second, maximum 256 bytes |
| Live connections | Shared cap; excess connections close immediately |

The body-read deadline includes admission wait. The queue timeout applies
separately to each gate.

Upload buffers hold the existing shared admission budget; scans also hold the
shared CPU budget. Buffer capacity is capped at the payload limit, with up to
twice that capacity temporarily held during growth. clamd deliberately bypasses
verdict caching/coalescing so scanner errors remain distinguishable from clean
results. It invokes the shared core once; it does not add a second verdict engine.

Shutdown stops listeners and uploads, then drains active scans. Socket closure
cannot forcibly stop a native scan; it retains its buffer and permits until it
returns. A failed drain makes daemon shutdown unsuccessful and conservatively
skips scanner cleanup. That cleanup currently stops feed refreshers only; the
guard also protects future native-resource cleanup while a call remains live.
HTTP, ICAP and clamd shut down concurrently within one shared grace deadline.
Resource exhaustion during accept retries with bounded backoff; unexpected
terminal listener failures increment `mailstrix_clamd_accept_errors_total`.
Full rule names are not sent on the wire;
use verbose server logs and the existing HTTP detail surfaces when needed.

Unsupported: path scans, FD passing, `IDSESSION`, `END`, administrative commands,
ClamAV database-version emulation, TLS and authentication. VERSION parsers that
require a `ClamAV` prefix are incompatible. `clamdscan --multiscan --stream`
requires sessions and is not supported. See the official
[client mode documentation](https://docs.clamav.net/manual/Usage/ClamdProtocol.html#clamdscan-behavior).

## Qualification

Observed on Linux with ClamAV `clamdscan 1.5.3` and Python `clamd==1.0.2`:
both clients submitted inert clean and locally matched streams over Unix and
loopback TCP, rejected an oversized stream, and reconnected successfully.
The same clients also observed scanner ERROR through an injected ScanEngine
failure in the adapter fixture. A separate native `strixd` run used one generated
YARA rule and the harmless string `MAILSTRIX-CLAMD-MATCH`; no malware samples or
production deployment were involved. Native shutdown removed its Unix socket.
These observations do not qualify all clamd clients or the deployment examples.

The opt-in Go probe runs [test_clients.py](test_clients.py) using installed
clients. It fails if the requested tools are absent; ordinary unit tests do not
need those tools. No dependency is added to the production artifact.

```sh
python3 -m venv /tmp/mailstrix-clamd-clients
/tmp/mailstrix-clamd-clients/bin/python -m pip install clamd==1.0.2
MAILSTRIX_TEST_CLAMD_PYTHON=/tmp/mailstrix-clamd-clients/bin/python \
  go test ./internal/mailstrix -run '^TestClamdRealClients$' -count=1 -v
```

The separate `clamdscan` executable must already be on PATH. The probe uses
ephemeral local listeners, a 4096-byte cap and generated inert messages.
