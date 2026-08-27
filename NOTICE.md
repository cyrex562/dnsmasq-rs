# Notice

`dnsmasq-rs` is Copyright (C) 2024-2026 Josh Madden, and is licensed under
the GNU General Public License, version 3 or (at your option) any later
version. See [`LICENSE`](LICENSE) for the full, unmodified license text.

## Derivative work of dnsmasq

`dnsmasq-rs` is a Rust port of [dnsmasq](https://www.thekelleys.org.uk/dnsmasq/),
a lightweight DNS forwarder and DHCP/TFTP server. Large parts of this
project translate dnsmasq's C implementation — its algorithms, control
flow, wire-format handling, and (where doing so aids review) its naming —
into Rust, rather than reimplementing its behavior from a clean-room
specification. As such, `dnsmasq-rs` is a derivative work of dnsmasq for
copyright purposes, and is licensed accordingly.

dnsmasq itself carries the notice:

    dnsmasq is Copyright (c) 2000-2025 Simon Kelley

and is dual-licensed under the GNU General Public License, version 2, or
(at the licensee's option) version 3 — see
<https://www.thekelleys.org.uk/dnsmasq/doc.html> and
<http://thekelleys.org.uk/git/dnsmasq.git> for the original project and its
own `COPYING`/`COPYING-v3` license texts. `dnsmasq-rs` exercises that
"at your option" clause and is released under GPLv3-or-later.

Simon Kelley and dnsmasq's other contributors are not affiliated with this
project and have not reviewed or endorsed it.

## What's original to this project

Some parts of `dnsmasq-rs` have no upstream `dnsmasq` counterpart and are
original work rather than a translation of its C source — see the module
map in [`CLAUDE.md`](CLAUDE.md) for specifics (for example: `web_api.rs`,
`web_ui.rs`, `metrics_api.rs`, `yaml_config.rs`, and the parity-testing
tooling under `parity/`). Those are original contributions by this
project's author(s). The project as a whole — including those modules,
since they are compiled together with and depend on the ported core — is
distributed under GPLv3-or-later.
