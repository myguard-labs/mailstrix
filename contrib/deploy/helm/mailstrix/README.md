# strixd Helm chart

A Helm v3 chart for [mailstrix](https://github.com/myguard-labs/mailstrix) — a single
Go HTTP daemon that scans mail content with YARA rules (plus optional abuse.ch
threat-intel feeds) as an internal backend for the rspamd `mailstrix.lua` plugin.

It mirrors the security posture and configuration surface of the reference
[`docker/docker-compose.yml`](../../../docker/docker-compose.yml): distroless
nonroot user, immutable rootfs, all capabilities dropped, no privilege
escalation, `RuntimeDefault` seccomp.

> **ClusterIP only by design.** strixd is not web-facing — it is a scan backend
> for rspamd. The chart ships no Ingress and exposes a `ClusterIP` Service.
> Reach it in-cluster at
> `http://<release>-mailstrix.<namespace>.svc.cluster.local:8079`.

## Install

```bash
# From the repo root:
install -d -m 700 .mailstrix-secrets
(umask 077; openssl rand -hex 32 > .mailstrix-secrets/token)
kubectl create namespace mailscreen
kubectl -n mailscreen create secret generic strixd-token \
  --from-file=token=.mailstrix-secrets/token
helm install strixd ./contrib/deploy/helm/mailstrix \
  --namespace mailscreen --create-namespace \
  --set token.existingSecret=strixd-token --set token.secretKey=token
```

Or with another pre-created token Secret:

```bash
helm install strixd ./contrib/deploy/helm/mailstrix \
  --namespace mailscreen \
  --set token.existingSecret=strixd-token --set token.secretKey=token
```

Enable the abuse.ch feeds (one free key from <https://auth.abuse.ch/> enables
URLhaus + MalwareBazaar + ThreatFox):

```bash
helm install strixd ./contrib/deploy/helm/mailstrix \
  --namespace mailscreen \
  --set token.existingSecret=strixd-token \
  --set abuseChKey.value=YOUR_AUTH_KEY \
  --set resources.limits.memory=768Mi   # MalwareBazaar full feed needs headroom
```

## Values

| Key | Default | Description |
| --- | --- | --- |
| `image.repository` | `myguard-labs/mailstrix` | Image repo (use `:debian` tag for glibc variant). |
| `image.tag` | `""` | Falls back to `Chart.appVersion` (`1.2.0`). |
| `image.pullPolicy` | `IfNotPresent` | |
| `replicaCount` | `1` | `>1` requires `redis.url` for a shared verdict cache. |
| `token.value` | `""` | Inline secret; prefer `existingSecret` to avoid CLI exposure. |
| `token.existingSecret` | `""` | Use a pre-existing Secret instead (takes precedence). |
| `token.secretKey` | `token` | Key within the Secret. |
| `abuseChKey.value` | `""` | abuse.ch Auth-Key; wires all three `*_KEY_FILE` envs. |
| `abuseChKey.existingSecret` / `.secretKey` | `""` / `key` | Use an existing Secret. |
| `config.*` | `""` | Optional `MAILSTRIX_*` tunables; only non-empty values are emitted. |
| `redis.url` / `redis.prefix` | `""` | Shared verdict cache (Valkey/Redis). |
| `cache.enabled` | `false` | Mount a writable `MAILSTRIX_CACHE_DIR` (emptyDir or PVC). |
| `service.type` / `service.port` | `ClusterIP` / `8079` | |
| `resources.requests` | `100m` / `256Mi` | |
| `resources.limits` | `1` / `512Mi` | Bump memory to ~768Mi with MalwareBazaar full feed. |
| `serviceMonitor.enabled` | `false` | Prometheus-Operator ServiceMonitor scraping `/metrics`. |
| `podSecurityContext` / `securityContext` | hardened | nonroot 65532, read-only rootfs, drop ALL caps, seccomp RuntimeDefault. |
| `nodeSelector` / `tolerations` / `affinity` | `{}` / `[]` / `{}` | Scheduling passthrough. |

Authentication is intentionally optional in strixd. With neither token value
set, the chart renders an **open** internal scanner: a valid `/scan` request can
return HTTP 200 without credentials, and strixd logs a startup warning. Use
that mode only on a trusted private cluster network. With a token configured,
missing or incorrect credentials return HTTP 401.

### Endpoints

`/scan` (auth), `/metrics`, `/health` (liveness), `/ready` (readiness),
`/version`. Probes use `httpGet` on `/health` and `/ready`; the image also has a
`strixd health` exec subcommand (used by the docker healthcheck).

## Observability

The repo ships matching monitoring assets:

- Prometheus alerts: [`contrib/deploy/prometheus/mailstrix-alerts.yml`](../../prometheus/mailstrix-alerts.yml)
- Grafana dashboard: [`contrib/deploy/grafana/mailstrix-dashboard.json`](../../grafana/mailstrix-dashboard.json)

Set `serviceMonitor.enabled=true` to have Prometheus Operator scrape `/metrics`.

## See also

- Project root README: [`../../../README.md`](../../../README.md)
- Reference docker-compose: [`../../../docker/docker-compose.yml`](../../../docker/docker-compose.yml)
- Prometheus alerts: [`../../prometheus/`](../../prometheus/)
- Grafana dashboard: [`../../grafana/`](../../grafana/)
