FROM debian:bookworm-slim AS build

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential ca-certificates make gcc libc6-dev git \
    && rm -rf /var/lib/apt/lists/*

# Fetched at build time rather than vendored into this repo (issue #169 —
# dnsmasq-rs is a derivative work of this GPLv2/v3 source and is licensed
# accordingly, see NOTICE.md, but that doesn't mean we should also carry a
# full copy of upstream's own source tree in our git history). Pinned to the
# exact tag this port targets for parity, so results stay reproducible
# rather than drifting with upstream's master.
ARG DNSMASQ_REF=v2.93test4
WORKDIR /src
RUN git clone --branch "$DNSMASQ_REF" --depth 1 http://thekelleys.org.uk/git/dnsmasq.git /src

# Keep the upstream comparison image lean and avoid optional subsystems that
# are unrelated to the first DNS-only parity lane.
RUN make COPTS="-DNO_TFTP -DNO_SCRIPT"

FROM debian:bookworm-slim

RUN useradd --system --uid 65532 --create-home dnsmasq

COPY --from=build /src/src/dnsmasq /usr/local/sbin/dnsmasq

USER dnsmasq
ENTRYPOINT ["/usr/local/sbin/dnsmasq"]
