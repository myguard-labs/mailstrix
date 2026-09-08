# Offline ClamAV adapter qualification

This optional prerequisite uses inert local text and one private test signature.
It does not yet connect ClamAV to the parity CLI, compare corpus observations,
measure accuracy, or qualify a representative corpus. Existing CLI reports keep
their meaning and privacy defaults.

Supply a JSON array of `[source_path, absolute_image_path]` pairs containing a
trusted local `/usr/bin/clamscan`, its ELF loader/shared libraries, and explicit
database files under `/db/`. The source installation is an operator-selected
input; this tool does not discover dependencies, install packages, download
images, update databases, run a daemon, or use a host scanner fallback. Do not
include credentials or arbitrary host directories. Example entries:

```json
[
  ["/usr/bin/clamscan", "/usr/bin/clamscan"],
  ["/lib64/ld-linux-x86-64.so.2", "/lib64/ld-linux-x86-64.so.2"],
  ["/var/lib/clamav/main.cvd", "/db/main.cvd"]
]
```

That shortened example is not a complete installation. Supply every needed
library and the intended DB files. Missing dependencies fail qualification.

```sh
python3 -B -m unittest discover -s tools/parity -p 'clamav_adapter_test.py'
python3 -B tools/parity/qualify_clamav.py \
  --assets /path/to/assets.json --output /path/to/new-output
```

The new output directory retains normalized `rootfs.tar` snapshots, per-asset
SHA-256 inventories, engine-assets and DB-set identities, and
`qualification.json`. Source paths/timestamps do not enter inventories. Snapshots
are imported directly into local Docker images by immutable ID, without tags,
builds or registry access. Snapshots/images remain local for verification and
later explicit removal. Generated binary/DB assets do not belong in Git.

The signature-bearing image is separate from the unmodified DB image and has a
different DB identity. Its only addition is a signature for a literal inert
marker, checked against both that marker and a distinct negative input. The
second snapshot must match the first installation byte for byte apart from that
addition. A changed host installation invalidates the qualification.

Each observation uses one fresh container on the local Unix Docker socket:
network disabled, read-only root, numeric non-root user, all capabilities dropped,
no-new-privileges, no mounts, private cgroup/IPC namespaces, 64 processes, one CPU,
4 GiB memory with no extra swap, and a 512 MiB noexec/nosuid/nodev temporary
filesystem. The container configuration is checked before sending stdin.
Docker runs with an empty private client configuration and a stripped
environment, so host client proxies and credentials cannot enter the container.

This is a separate ClamAV envelope, not the 512 MiB Mailstrix or 256 MiB Python
allowance. The 4 GiB ceiling is qualified only for the exact frozen DB and these
inert inputs; the host must expose at least 6 GiB. No representative workload
capacity claim follows. The deliberately under-budget 32 MiB control must report
Docker's OOM state as `resource_limit`.

Input is bounded to 32 MiB and each output pipe to 64 KiB. Start/scan has a
45-second parent deadline; each create/inspect/remove/absence operation has its
own five-second deadline. Client termination has a five-second reap bound.
The container is removed and its absence checked independently on every path.
An inconclusive create or cleanup poisons the backend instance and retains the
exact generated container name for operator investigation. Removal must succeed;
the independent absence query still runs after failed removal. Cleanup failure
overrides any successful scanner response. Qualification exercises actual timeout,
missing-DB, max-file-size, and OOM cases, in addition to deterministic boundary
and cleanup controls. Neither sample-controlled output nor a timed-out process
can produce a completed no-detection observation.

`no_detection` means the pinned engine completed its invocation with the exact
`stdin: OK` response under the declared policy. It does not prove exhaustive
extraction, absence of malware, or inspection of every nested object. Every
configured engine limit is included in the receipt's argv, including the
embedded-PE, HTML/script normalization, ZIP type recognition, partition/icon,
HWP3, PCRE, and bytecode budgets. Optional components not supplied in the frozen
assets, such as an external RAR module, are not qualified. ClamAV's internal
`max-scantime` is disabled because its documented timeout behavior assumes
clean; the parent enforces elapsed time instead. Observed scan limits, heuristics,
timeouts, OOMs, malformed output, and errors remain excluded observations.

For the pinned historical ClamAV 1.5.3 DB, only the byte-exact known four-line
database-age warning may be retained as metadata instead of failing the scan.
The receipt keeps its full text and marks `database_stale=true`; it explicitly
does not qualify freshness or current accuracy. Any added diagnostic, changed
byte, or other warning fails the invocation. Qualification verifies the running
engine version before enabling this exception.

The snapshot contains an empty `/etc/clamav/certs` directory because 1.5.3
requires it even for legacy CVD verification. Default legacy signature
verification stays enabled. No detached-signature CA is installed, so this path
does not qualify detached-signature databases; verification failures remain
errors. The private unsigned test signature is declared only in its separate
qualification DB inventory.
