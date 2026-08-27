# systemd unit for dnsmasq-rs

`dnsmasq-rs.service` is a template unit for running `dnsmasq-rs` under
systemd. Upstream dnsmasq ships its own `contrib/systemd/dnsmasq.service`
(not vendored in this repo — see `NOTICE.md`) but this one isn't copied from
it; it's written from scratch against `dnsmasq-rs`'s actual CLI flags and
default behavior.

## Install

```sh
cargo build --release
install -m755 target/release/dnsmasq-rs /usr/local/bin/dnsmasq-rs
install -m644 contrib/systemd/dnsmasq-rs.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now dnsmasq-rs
```

Edit the unit's `ExecStart=` line first if your binary or config file live
somewhere else, or if you want `--user=`/`--group=` privilege-dropping set on
the command line rather than in `dnsmasq-rs.conf` itself.

## Notes

- `Type=simple` with `--keep-in-foreground` (`-k`): dnsmasq-rs stays in the
  foreground so systemd tracks it directly, rather than forking and writing
  a pid file for systemd to find (`Type=forking`) — simpler, and avoids the
  usual pid-file-race issues with that mode.
- The unit deliberately does not set `User=`/`Group=`. dnsmasq-rs needs root
  (or the commented-out capabilities in the unit) to bind ports 53/67 and,
  when DHCP/DHCPv6/RA is configured, open raw and netlink sockets — then
  drops to an unprivileged user/group itself via `--user=`/`--group=`, the
  same two-step privilege model upstream dnsmasq uses.
- `journalctl -u dnsmasq-rs` works with no extra configuration: dnsmasq-rs
  logs through `/dev/log` (syslog) by default, which `systemd-journald`
  forwards into the journal on virtually every modern distro. Building with
  the `journald` cargo feature and adding `--log-facility=journald` logs
  directly to the journal via a native client instead, if you'd rather skip
  the syslog hop.
- `ExecReload=` sends `SIGHUP`, which triggers a real config reload (cache
  flush, hosts/resolv/DHCP-hosts-options-ethers re-read, and propagation to
  the live DNS/DHCP dispatch loops) — see `CLAUDE.md`'s "Runtime flow"
  section for exactly what that does and doesn't re-read.
