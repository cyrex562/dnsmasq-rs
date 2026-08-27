# dnsmasq-rs

`dnsmasq-rs` is a Rust port of [dnsmasq](https://www.thekelleys.org.uk/dnsmasq/),
the popular DNS forwarder and DHCP/TFTP server, targeting behavioral parity
with the supported feature set. It is a derivative work of dnsmasq — see
[`NOTICE.md`](NOTICE.md) for attribution and licensing details — not an
unrelated reimplementation.

## Features

- DNS forwarding with caching
- DHCP server with support for static and dynamic IP address allocation
- Lightweight and efficient
- Easy to configure and extend

## Installation

Build the binary from source:

```sh
cargo build --release
```

## Usage

`dnsmasq-rs` is a standalone daemon, invoked the same way as upstream
`dnsmasq`:

```sh
dnsmasq-rs --conf-file=/etc/dnsmasq-rs.conf
```

## Running as a service

A systemd unit template is provided in [`contrib/systemd/`](contrib/systemd/)
for running the `dnsmasq-rs` binary as a service on systemd-based Linux
distributions.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request on GitHub.

## License

This project is licensed under the GNU General Public License, version 3
or (at your option) any later version. See [`LICENSE`](LICENSE) for the
full text and [`NOTICE.md`](NOTICE.md) for attribution — `dnsmasq-rs` is a
derivative work of dnsmasq, Copyright (c) 2000-2025 Simon Kelley, itself
dual-licensed GPLv2-or-v3.