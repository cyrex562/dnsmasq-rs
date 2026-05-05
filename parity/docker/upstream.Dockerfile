FROM debian:bookworm-slim AS build

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential ca-certificates make gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY original_dnsmasq_src/dnsmasq-master/ /src/

# Keep the upstream comparison image lean and avoid optional subsystems that
# are unrelated to the first DNS-only parity lane.
RUN make COPTS="-DNO_TFTP -DNO_SCRIPT"

FROM debian:bookworm-slim

RUN useradd --system --uid 65532 --create-home dnsmasq

COPY --from=build /src/src/dnsmasq /usr/local/sbin/dnsmasq

USER dnsmasq
ENTRYPOINT ["/usr/local/sbin/dnsmasq"]
