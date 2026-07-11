# syntax=docker/dockerfile:1
# strixd — YARA scanner backend for rspamd.
#
# Multi-stage: a Debian builder compiles libyara statically and builds strixd
# with CGO against it (go-yara, yara_static tag), so the final image is a
# distroless nonroot container that needs no libyara at runtime. Public YARA
# rulesets are baked in at build time; a daily rebuild (CACHEBUST) re-pulls the
# latest. Override YARAFORGE_SET/YARAFORGE_URL / SIGBASE_REF to pin.

ARG GO_VERSION=1.25.12
ARG YARA_VERSION=4.5.2

# ---- libyara (static) -------------------------------------------------------
FROM debian:bookworm-slim AS yara
ARG YARA_VERSION
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential automake libtool make pkg-config \
        libssl-dev curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL "https://github.com/VirusTotal/yara/archive/refs/tags/v${YARA_VERSION}.tar.gz" \
        | tar -xz -C /tmp
WORKDIR /tmp/yara-${YARA_VERSION}
# No --enable-magic / --enable-cuckoo: email-attachment scanning needs neither,
# and dropping them removes the libmagic/libjansson runtime deps so the
# distroless base-debian12 final image needs only glibc + libssl + libz. Crypto
# (--with-crypto) stays for the "hash" module many public rules use.
RUN ./bootstrap.sh \
    && CFLAGS="-O2 -flto -DNDEBUG" LDFLAGS="-flto" \
       ./configure --disable-shared --enable-static --with-crypto \
    && make -j"$(nproc)" && make install && ldconfig

# ---- go build ---------------------------------------------------------------
FROM golang:${GO_VERSION}-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc pkg-config libssl-dev zlib1g-dev libzstd-dev \
    && rm -rf /var/lib/apt/lists/*
# bring in the statically built libyara
COPY --from=yara /usr/local/lib/libyara.a /usr/local/lib/
COPY --from=yara /usr/local/include/yara.h /usr/local/include/
COPY --from=yara /usr/local/include/yara/ /usr/local/include/yara/
COPY --from=yara /usr/local/lib/pkgconfig/yara.pc /usr/local/lib/pkgconfig/
WORKDIR /src
COPY . .
# The yara_static tag makes go-yara link libyara.a; libyara's own deps
# (ssl/magic/jansson/z/zstd) and glibc stay dynamically linked and are provided
# by the distroless base-debian12 final image. A full -static glibc link is
# avoided on purpose: it makes dlopen/getaddrinfo fragile at runtime.
ENV CGO_ENABLED=1 \
    PKG_CONFIG="pkg-config --static"
# Reproducible, tamper-evident dependency resolution. Runs after `COPY . .` so the
# source-vendored ./third_party/oleparse replace target is present. No `|| true`:
# a failed download must fail the build, not silently ship a partial module set.
#   go mod download — fetch modules into the cache-mounted /go/pkg/mod
#   go mod verify   — check them against the committed go.sum hashes
#   tidy-drift gate — assert the COMMITTED go.mod/go.sum are already tidy; tidy
#     here would mutate them and mask drift. Fix = commit tidy files, not regen.
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download && go mod verify \
    && cp go.mod /tmp/go.mod.orig && cp go.sum /tmp/go.sum.orig \
    && go mod tidy \
    && diff -u /tmp/go.mod.orig go.mod \
    && diff -u /tmp/go.sum.orig go.sum \
    && rm /tmp/go.mod.orig /tmp/go.sum.orig
ARG VERSION=dev
ARG YARA_VERSION
# Two binaries: the CGO/libyara server (strixd), and the lean Sieve/LDA client
# (strix-scan) built CGO-free — pure Go, no libyara, a small static binary for a
# mail-delivery host that only POSTs to a central strixd. main.libyaraVersion is
# baked from YARA_VERSION so `fetch-rules` can refuse a .yac built against a
# different libyara.
# Mount the Go module + build caches so an unchanged-source rebuild reuses
# compiled packages instead of recompiling cold every CI run.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -tags yara_static \
        -ldflags "-s -w -X main.version=${VERSION} -X main.libyaraVersion=${YARA_VERSION}" \
        -o /out/strixd ./cmd/strixd \
    && CGO_ENABLED=0 go build \
        -ldflags "-s -w -X main.version=${VERSION}" \
        -o /out/strix-scan ./cmd/strix-scan

# ---- tests (built into the image build so CI fails on a bad commit) ---------
FROM build AS test
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go vet ./... \
    && go test -race -tags yara_static ./...

# ---- binary export (release artifacts; not part of the runtime image) -------
# `docker buildx build --target bin --platform linux/amd64,linux/arm64
#  --output type=local,dest=dist .` drops just the strixd binary per arch.
FROM scratch AS bin
COPY --from=build /out/strixd /strixd
COPY --from=build /out/strix-scan /strix-scan

# ---- rules ------------------------------------------------------------------
# FROM the yara stage so we have `yarac` (the libyara compiler) from the exact
# same libyara build go-yara links against — a .yac is version-locked to its
# compiler. Fetch the public rulesets, then precompile them into one .yac so the
# runtime never compiles ~10k rules itself (that peaked >3 GB and OOM-killed).
FROM yara AS rules
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates unzip python3 \
    && rm -rf /var/lib/apt/lists/*
# filter-rules.py must sit beside fetch-rules.sh (resolved via $(dirname "$0"))
# so the `mail` profile per-rule mail-relevance/license filter runs.
COPY docker/fetch-rules.sh docker/compile-rules.sh docker/filter-rules.py /usr/local/bin/
# Repo-tracked local rules (our own heuristics, e.g. the mraptor-style maldoc
# rule) baked alongside the fetched public sets so they ship in the seed .yac.
COPY docker/local-rules/ /usr/local/share/mailstrix-local-rules/
RUN chmod +x /usr/local/bin/fetch-rules.sh /usr/local/bin/compile-rules.sh /usr/local/bin/filter-rules.py
ARG CACHEBUST=unset
# LOCAL_ONLY=1 skips all network rule fetches; only docker/local-rules/ are
# compiled into the seed .yac. GitHub CI + release builds set this (the heavy
# public bundle is built by the local nightly cron and shipped via the
# rules-current release, pulled at runtime by --fetch-rules).
ARG LOCAL_ONLY=0
# PERF-25 rule profile: mail (default, conservative prune) | full (every rule).
ARG MAILSTRIX_PROFILE=mail
ARG YARAFORGE_SET=full
# Legacy alias: YARAFORGE_FILTER=0 forces the `full` profile (back-compat).
ARG YARAFORGE_FILTER=1
ARG YARAFORGE_URL=
ARG SIGBASE_REF=master
ARG ANYRUN_REF=main
ARG ANYRUN=1
ARG DIDIER_REF=master
ARG DIDIER=1
ARG BARTBLAZE_REF=master
ARG BARTBLAZE=1
ARG INQUEST_REF=main
ARG INQUEST=1
ARG CAPE=1
ARG CAPE_REF=master
ARG YARAIFY=1
ARG YARAIFY_URL=
RUN LOCAL_ONLY="${LOCAL_ONLY}" MAILSTRIX_PROFILE="${MAILSTRIX_PROFILE}" \
        YARAFORGE_SET="${YARAFORGE_SET}" YARAFORGE_FILTER="${YARAFORGE_FILTER}" YARAFORGE_URL="${YARAFORGE_URL}" SIGBASE_REF="${SIGBASE_REF}" \
        ANYRUN="${ANYRUN}" ANYRUN_REF="${ANYRUN_REF}" \
        DIDIER="${DIDIER}" DIDIER_REF="${DIDIER_REF}" \
        BARTBLAZE="${BARTBLAZE}" BARTBLAZE_REF="${BARTBLAZE_REF}" \
        INQUEST="${INQUEST}" INQUEST_REF="${INQUEST_REF}" \
        CAPE="${CAPE}" CAPE_REF="${CAPE_REF}" \
        YARAIFY="${YARAIFY}" YARAIFY_URL="${YARAIFY_URL}" \
        /usr/local/bin/fetch-rules.sh /rules/src \
    && cp /usr/local/share/mailstrix-local-rules/*.yara /rules/src/ \
    && /usr/local/bin/compile-rules.sh /rules/src /rules/compiled.yac \
    && mkdir -p /rules/local-src \
    && cp /usr/local/share/mailstrix-local-rules/*.yara /rules/local-src/ \
    && /usr/local/bin/compile-rules.sh /rules/local-src /rules/local.yac \
    && rm -rf /rules/src /rules/local-src \
    && install -d -o 65532 -g 65532 /var/cache/mailstrix \
    && yarac --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 > /rules/libyara.version

# ---- rules export (for the home rule-generation cron; not a runtime image) --
# `docker buildx build --target rules-export --output type=local,dest=out .`
# drops the compiled bundle + the exact libyara/yarac version that wrote it, so
# docker/generate-rules.sh can build the publish manifest. A .yac only loads on a
# matching libyara, so the version is authoritative. Separate from `final` — a
# normal image build never produces this.
FROM scratch AS rules-export
COPY --from=rules /rules/compiled.yac /compiled.yac
COPY --from=rules /rules/libyara.version /libyara.version
COPY --from=rules /rules/sources.json /sources.json

# ---- final (distroless, nonroot) -------------------------------------------
FROM gcr.io/distroless/base-debian12:nonroot AS final
COPY --from=build /out/strixd /usr/local/bin/strixd
# strix-scan (the lean CGO-free HTTP client) ships in PATH too, so the same image
# can both SERVE (strixd) and be a labelling client via `docker exec <ctr>
# strix-scan -url http://127.0.0.1:8079 -json -`. Pure-Go, no extra runtime deps.
COPY --from=build /out/strix-scan /usr/local/bin/strix-scan
# The compiled bundle ships as a READ-ONLY seed under /usr/share/mailstrix. At
# startup strixd copies it into the writable cache dir (MAILSTRIX_CACHE_DIR) when that
# is empty/unreadable and serves from there, so a wiped cache bindmount self-heals
# to this tested ruleset and a later `--fetch-rules` can refresh the cache copy
# without touching the image. Mount /var/cache/mailstrix writable (the rootfs stays
# read-only); on a tmpfs mount it simply reseeds from /usr/share each boot.
# Owned root on purpose: the seed is the trust anchor / immutable fallback, so the
# nonroot service user must NOT be able to modify it even on a writable overlay
# rootfs (only /var/cache/mailstrix is service-writable). No --chown = root:root; the
# file stays world-readable (0644 from yarac) so nonroot can still read it to seed.
COPY --from=rules /rules/compiled.yac /usr/share/mailstrix/compiled.yac
# local.yac = ONLY the in-repo high-signal local rules, compiled separately. It is
# the targeted ruleset for the oversized-buffer cost gate (MAILSTRIX_BIGFILE_THRESHOLD):
# a multi-MB buffer scanned against the full ~12k-rule bundle is unbounded and can
# time out (fail-open => malware MISSED), so over the threshold strixd scans the raw
# bytes against this small set instead — fast + the local dropper heuristics fire.
COPY --from=rules /rules/local.yac /usr/share/mailstrix/local.yac
COPY --from=rules /rules/sources.json /usr/share/mailstrix/sources.json
COPY --from=build /src/NOTICE /usr/share/mailstrix/NOTICE
# A writable cache dir owned by nonroot, so strixd can seed even with no bindmount
# (a bindmount or tmpfs at /var/cache/mailstrix simply overlays it).
COPY --from=rules --chown=nonroot:nonroot /var/cache/mailstrix /var/cache/mailstrix
ENV MAILSTRIX_SEED_RULES=/usr/share/mailstrix/compiled.yac \
    MAILSTRIX_BIGFILE_RULES=/usr/share/mailstrix/local.yac \
    MAILSTRIX_CACHE_DIR=/var/cache/mailstrix \
    MAILSTRIX_HOST=0.0.0.0 \
    MAILSTRIX_PORT=8079
EXPOSE 8079
USER nonroot
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["/usr/local/bin/strixd", "health"]
ENTRYPOINT ["/usr/local/bin/strixd"]
CMD ["serve"]
