# strixd Helm chart

A Helm v3 chart for [mailstrix](https://github.com/eilandert/mailstrix) — a single
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
helm install strixd ./contrib/deploy/helm/mailstrix \
  --namespace mailscreen --create-namespace \
  --set token.value=$(openssl rand -hex 32)
```

Or with a pre-created token Secret (recommended for production):

```bash
kubectl -n mailscreen create secret generic strixd-token --from-literal=token=...
helm install strixd ./contrib/deploy/helm/mailstrix \
  --namespace mailscreen \
  --set token.existingSecret=strixd-token --set token.secretKey=token
```

Enable the abuse.ch feeds (one free key from <https://auth.abuse.ch/> enables
URLhaus + MalwareBazaar + ThreatFox):

```bash
helm install strixd ./contrib/deploy/helm/mailstrix \
  --set token.value=... \
  --set abuseChKey.value=YOUR_AUTH_KEY \
  --set resources.limits.memory=768Mi   # MalwareBazaar full feed needs headroom
```

## Values

| Key | Default | Description |
| --- | --- | --- |
| `image.repository` | `eilandert/mailstrix` | Image repo (use `:debian` tag for glibc variant). |
| `image.tag` | `""` | Falls back to `Chart.appVersion` (`1.2.0`). |
| `image.pullPolicy` | `IfNotPresent` | |
| `replicaCount` | `1` | `>1` requires `redis.url` for a shared verdict cache. |
| `token.value` | `""` | Inline shared secret; chart creates a Secret + wires `MAILSTRIX_TOKEN_FILE`. |
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

Without a token, the chart still renders, but strixd returns **HTTP 503** on
every `/scan` — see the post-install notes.

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
