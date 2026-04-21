FROM rust:1-bookworm AS build

WORKDIR /app
COPY . /app
RUN cargo build --release --bin dnsmasq-rs

FROM debian:bookworm-slim

COPY --from=build /app/target/release/dnsmasq-rs /usr/local/bin/dnsmasq-rs

ENTRYPOINT ["/usr/local/bin/dnsmasq-rs"]
