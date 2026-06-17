# yarad — YARA scanner backend for rspamd.
#
# Multi-stage: a Debian builder compiles libyara statically and builds yarad
# with CGO against it (go-yara, yara_static tag), so the final image is a
# distroless nonroot container that needs no libyara at runtime. Public YARA
# rulesets are baked in at build time; a daily rebuild (CACHEBUST) re-pulls the
# latest. Override YARAFORGE_URL / SIGBASE_REF to pin.

ARG GO_VERSION=1.25
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
    && ./configure --disable-shared --enable-static --with-crypto \
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
COPY go.mod go.sum* ./
RUN go mod download || true
COPY . .
# The yara_static tag makes go-yara link libyara.a; libyara's own deps
# (ssl/magic/jansson/z/zstd) and glibc stay dynamically linked and are provided
# by the distroless base-debian12 final image. A full -static glibc link is
# avoided on purpose: it makes dlopen/getaddrinfo fragile at runtime.
ENV CGO_ENABLED=1 \
    PKG_CONFIG="pkg-config --static"
RUN go mod tidy
ARG VERSION=dev
RUN go build -tags yara_static \
        -ldflags "-s -w -X main.version=${VERSION}" \
        -o /out/yarad ./cmd/yarad

# ---- tests (built into the image build so CI fails on a bad commit) ---------
FROM build AS test
RUN go vet ./... \
    && go test -race -tags yara_static ./...

# ---- binary export (release artifacts; not part of the runtime image) -------
# `docker buildx build --target bin --platform linux/amd64,linux/arm64
#  --output type=local,dest=dist .` drops just the yarad binary per arch.
FROM scratch AS bin
COPY --from=build /out/yarad /yarad

# ---- rules ------------------------------------------------------------------
# FROM the yara stage so we have `yarac` (the libyara compiler) from the exact
# same libyara build go-yara links against — a .yac is version-locked to its
# compiler. Fetch the public rulesets, then precompile them into one .yac so the
# runtime never compiles ~10k rules itself (that peaked >3 GB and OOM-killed).
FROM yara AS rules
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates unzip \
    && rm -rf /var/lib/apt/lists/*
COPY docker/fetch-rules.sh docker/compile-rules.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/fetch-rules.sh /usr/local/bin/compile-rules.sh
ARG CACHEBUST=unset
ARG YARAFORGE_URL=
ARG SIGBASE_REF=master
ARG ANYRUN_REF=main
ARG ANYRUN=1
ARG DIDIER_REF=master
ARG DIDIER=1
ARG BARTBLAZE_REF=master
ARG BARTBLAZE=1
RUN YARAFORGE_URL="${YARAFORGE_URL}" SIGBASE_REF="${SIGBASE_REF}" \
        ANYRUN="${ANYRUN}" ANYRUN_REF="${ANYRUN_REF}" \
        DIDIER="${DIDIER}" DIDIER_REF="${DIDIER_REF}" \
        BARTBLAZE="${BARTBLAZE}" BARTBLAZE_REF="${BARTBLAZE_REF}" \
        /usr/local/bin/fetch-rules.sh /rules/src \
    && /usr/local/bin/compile-rules.sh /rules/src /rules/compiled.yac \
    && rm -rf /rules/src

# ---- final (distroless, nonroot) -------------------------------------------
FROM gcr.io/distroless/base-debian12:nonroot AS final
COPY --from=build /out/yarad /usr/local/bin/yarad
COPY --from=rules --chown=nonroot:nonroot /rules/compiled.yac /rules/compiled.yac
ENV YARAD_RULES=/rules/compiled.yac \
    YARAD_HOST=0.0.0.0 \
    YARAD_PORT=8079
EXPOSE 8079
USER nonroot
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["/usr/local/bin/yarad", "health"]
ENTRYPOINT ["/usr/local/bin/yarad"]
CMD ["serve"]
