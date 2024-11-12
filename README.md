# dnsmasq

`dnsmasq-rs` is a Rust implementation of the popular DNS forwarder and DHCP server, dnsmasq. This project aims to provide a high-performance, reliable, and easy-to-use DNS and DHCP server for Rust developers.

## Features

- DNS forwarding with caching
- DHCP server with support for static and dynamic IP address allocation
- Lightweight and efficient
- Easy to configure and extend

## Installation

To use `dnsmasq-rs`, add it to your `Cargo.toml`:

```toml
[dependencies]
dnsmasq-rs = "0.1.0"
```

## Usage

Here is a simple example of how to use `dnsmasq-rs`:

```rust
use dnsmasq_rs::Dnsmasq;

fn main() {
    let mut dnsmasq = Dnsmasq::new();
    dnsmasq.start().expect("Failed to start dnsmasq");
}
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request on GitHub.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.