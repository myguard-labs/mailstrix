# yarad — YARA malware scanning for rspamd

[![CI](https://github.com/eilandert/rspamd-yarad/actions/workflows/ci.yml/badge.svg)](https://github.com/eilandert/rspamd-yarad/actions/workflows/ci.yml)

A small HTTP service that scans mail with [YARA](https://virustotal.github.io/yara/) — the malware-detection rule engine — against ~10,000+ curated public rules. `POST /scan` a message or attachment; get back the rules that matched.

YARA matches the *shape* of a file (PE imports, section entropy, embedded magic), not a brittle literal string — a rule survives the next variant. yarad compiles those rules (libyara modules and all) and runs them over your mail, out of process, so the MTA never blocks on C code.

**GitHub:** <https://github.com/eilandert/rspamd-yarad>
**Article:** [YARA malware scanning in rspamd](https://deb.myguard.nl/2026/06/yara-malware-scanning-rspamd-yarad/)

## Quick start

```sh
docker run -d --name yarad \
    -e YARAD_TOKEN=changeme \
    -p 8079:8079 \
    eilandert/rspamd-yarad

printf 'hello' | curl -s -H 'X-YARAD-Token: changeme' \
    --data-binary @- http://127.0.0.1:8079/scan
# -> {"matches":[]}
```

## What it does

- **~10k+ public rules baked in** — YARA-Forge, signature-base, ANY.RUN, Didier Stevens, bartblaze, InQuest; precompiled `.yac`, daily refresh
- **Decompresses Office macros** — MS-OVBA VBA from `.docm`/`.xlsm`/`.doc`/`.xls`; scans the cleartext
- **Cracks open containers** — OLE2/OOXML, RTF `\objdata`, OLE Package, MSI, Outlook `.msg`, OneNote, PDF (FlateDecode), `.lnk`, VBE/JSE, nested archives (zip/7z/rar/gz/tar)
- **Maldoc heuristics** — mraptor-style autoexec∧write∧execute, VBA shellcode API, suspicious keyword count, VBA stomping, Equation Editor exploit, remote-template injection, DDE/DDEAUTO fields, XLM hidden macrosheets, LOLBin/WMI/PowerShell intent rules, UserForm/DocProps payload extraction
- **Static decode pass** — base64/hex/`StrReverse` single-layer decode over raw + extracted streams
- **abuse.ch feeds** — URLhaus malware-URL/host lookup + MalwareBazaar SHA256 hash lookup (cached, fail-open)
- **Tiered scoring** — `YARA_MALWARE` / `_EXPLOIT` / `_PHISHING` / `YARA` / `_SUSPICIOUS` + `URLHAUS_MALWARE_URL`; tune weights per tier in rspamd
- **Verdict cache** — SHA256-keyed LRU+TTL, request coalescing, optional Redis/Valkey L2
- **Fails open, always** — a scan error, timeout, or libyara panic = "no match"; never blocks mail
- **Observable** — `/health`, `/ready`, `/version`, Prometheus `/metrics` (scans, matches, cache, per-extractor counters, rule staleness)
- **Updatable rules without rebuild** — `yarad fetch-rules` + SIGHUP

## Two integration paths

| Path | When | How |
|------|------|-----|
| **rspamd** (SMTP time) | scan everything, reject by score | async `yara.lua` plugin POSTs each message/part → hits become weighted symbols |
| **Dovecot/Sieve** (delivery) | scan after spam filter, quarantine | `yarad-scan` CGO-free client, exit-code verdict, Sieve `execute` rule |

Both are shipped in the repo under [`rspamd/`](https://github.com/eilandert/rspamd-yarad/tree/main/rspamd) and [`sieve/`](https://github.com/eilandert/rspamd-yarad/tree/main/sieve).

## Configuration

Every setting is an env var and a CLI flag (flag > env > default).

| Env | Default | Meaning |
|-----|---------|---------|
| `YARAD_TOKEN[_FILE]` | — | shared secret for `/scan` |
| `YARAD_RULES` | baked `.yac` | precompiled rule bundle |
| `YARAD_RULES_DIR` | `/rules` | dir of `*.yar` files (compiled at boot + SIGHUP) |
| `YARAD_SCAN_TIMEOUT` | `8s` | per-request libyara budget |
| `YARAD_MAX_CONCURRENT` | auto (CPU count) | max concurrent scans |
| `YARAD_MAX_BODY` | `8 MiB` | max request body |
| `YARAD_CACHE_TTL` | `600s` | verdict cache TTL; `0` disables |
| `YARAD_REDIS_URL` | — | optional shared L2 cache |
| `YARAD_URLHAUS_KEY[_FILE]` | — | abuse.ch key; enables URLhaus lookup |
| `YARAD_MBAZAAR_KEY[_FILE]` | — | abuse.ch key; enables MalwareBazaar lookup |
| `YARAD_RULE_DENYLIST` | `http` | comma-sep rule names to suppress |
| `YARAD_RULE_ALLOWLIST` | — | comma-sep rule names to force log-only |

Full list: [README § Configuration](https://github.com/eilandert/rspamd-yarad#configuration)

## Sizing

| Profile | `MAX_CONCURRENT` | `mem_limit` | Redis | p95 |
|---------|------------------|-------------|-------|-----|
| **Small** (<100 msgs/min) | `2` | `128m` | optional | <500 ms |
| **Medium** (100–1000) | auto | `256m` | recommended | <300 ms |
| **Large** (>1000) | auto, multi-replica | `512m+` | required | <200 ms |

Peak memory ≈ `MAX_CONCURRENT × MAX_BODY + 64 MiB`. MalwareBazaar adds ~40 MiB + ~150 MiB transient on refresh.

## Production compose

```yaml
yarad:
  image: eilandert/rspamd-yarad:latest
  container_name: yarad
  restart: unless-stopped
  read_only: true
  mem_limit: 512m
  pids_limit: 256
  cap_drop: [ALL]
  security_opt: [no-new-privileges:true]
  tmpfs:
    - /tmp:mode=1777
    - /var/cache/yarad:mode=1777
  environment:
    YARAD_TOKEN_FILE: /run/yarad/token
    YARAD_MAX_CONCURRENT: "4"
  volumes:
    - ./config/yarad/token:/run/yarad/token:ro
```

## Image details

- **Base:** distroless (Debian), nonroot, read-only rootfs
- **Size:** ~89 MB
- **Arch:** amd64
- **libyara:** statically linked (no runtime dependency)
- **Healthcheck:** built-in (`/health`)

## Rules

Six public rulesets baked at build time (daily rebuild). Full credit to the authors — yarad only packages their work:

| Ruleset | License |
|---------|---------|
| [YARA-Forge](https://github.com/YARAHQ/yara-forge) | aggregator (per-rule upstream) |
| [signature-base](https://github.com/Neo23x0/signature-base) | DRL 1.1 |
| [ANY.RUN](https://github.com/anyrun/YARA) | public detection rules |
| [Didier Stevens](https://github.com/DidierStevens/DidierStevensSuite) | public domain |
| [bartblaze](https://github.com/bartblaze/Yara-rules) | MIT |
| [InQuest](https://github.com/InQuest/yara-rules-vt) | MIT |

Plus local maldoc/intent heuristics in `docker/local-rules/`.

## See also

- **[gozer](https://github.com/eilandert/gozer)** — DCC/Razor/Pyzor sibling backend
- **[rspamd-olefy](https://github.com/eilandert/rspamd-olefy)** — parallel oletools deep-scan scorer
- **[Dovecot/Sieve example](https://github.com/eilandert/rspamd-yarad/tree/main/sieve)** — delivery-time quarantine
- **[Article](https://deb.myguard.nl/2026/06/yara-malware-scanning-rspamd-yarad/)** — full writeup on deb.myguard.nl

## License

yarad is [MIT](https://github.com/eilandert/rspamd-yarad/blob/main/LICENSE). Baked rule sets keep their own licenses (see table above).
