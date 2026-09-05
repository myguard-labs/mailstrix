# PERF-12 profiling rig — libyara built with YR_PROFILING_ENABLED + the full
# prod ruleset (the SAME fetch-rules.sh / compile-rules.sh / local-rules the
# real image bakes), a C harness that scans a sample dir on ONE accumulating
# YR_SCANNER and dumps per-rule cost (descending). Use it to find rules whose
# string-matching phase dominates scan time (PERF-12 found 3 yaraify rules =
# 99.3% of all cost). NOT a runtime image — build context is the REPO ROOT.
#
#   docker build -f docker/profile/Dockerfile.profile -t strixd-profile .
#   docker run --rm -v /abs/path/to/samples:/samples strixd-profile > cost.tsv
#
# (samples = plaintext malware bodies; extract testdata/live-samples/*.zip with
# pyzipper, pw `infected`. See docker/profile/run-profile.sh for a wrapper.)
#
# Re-run after a redeploy: yaraify refetches latest daily, so new slow rules can
# appear — add any new top-cost offender to SLOW_RULE_DENYLIST in fetch-rules.sh.
ARG YARA_VERSION=4.5.2

FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171 AS yarap
ARG YARA_VERSION
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential automake libtool make gcc pkg-config \
        libssl-dev libjansson-dev libmagic-dev curl ca-certificates unzip git \
    && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL "https://github.com/VirusTotal/yara/archive/refs/tags/v${YARA_VERSION}.tar.gz" \
        -o /tmp/yara.tar.gz \
    && echo "1f87056fcb10ee361936ee7b0548444f7974612ebb0e681734d8de7df055d1ec  /tmp/yara.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/yara.tar.gz -C /tmp \
    && rm /tmp/yara.tar.gz
WORKDIR /tmp/yara-${YARA_VERSION}
RUN ./bootstrap.sh \
    && ./configure --enable-profiling --with-crypto \
    && make -j"$(nproc)" && make install && ldconfig

# the EXACT prod rule pipeline (single source of truth; context = repo root)
COPY docker/fetch-rules.sh docker/compile-rules.sh /usr/local/bin/
COPY docker/local-rules/ /usr/local/share/mailstrix-local-rules/
RUN chmod +x /usr/local/bin/fetch-rules.sh /usr/local/bin/compile-rules.sh
ARG CACHEBUST=unset
RUN /usr/local/bin/fetch-rules.sh /rules/src \
    && cp /usr/local/share/mailstrix-local-rules/*.yara /rules/src/ \
    && /usr/local/bin/compile-rules.sh /rules/src /rules/compiled.yac

COPY docker/profile/profile.c /tmp/profile.c
# pkg-config output is intentionally unquoted so it word-splits into flags (the
# SC2046 "warning" is the desired behaviour). CI hadolint only gates the prod
# docker/Dockerfile, not this rig.
RUN gcc -O2 /tmp/profile.c -o /usr/local/bin/profile \
      $(pkg-config --cflags --libs yara) -lyara -lssl -lcrypto -ljansson -lmagic -lm

# samples are mounted at run time (not baked — they're malware, gitignored):
#   docker run --rm -v /path/to/samples:/samples strixd-profile
CMD ["/usr/local/bin/profile", "/rules/compiled.yac", "/samples"]
