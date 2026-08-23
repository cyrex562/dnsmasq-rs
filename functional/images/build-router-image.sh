#!/usr/bin/env bash
set -euo pipefail

# Customizes the fetched OpenWrt base image into the router VM image
# functional/run.sh boots: installs a cross-compiled dnsmasq-rs, disables
# OpenWrt's own dnsmasq, and adds a custom classic (non-procd) rc.common
# service that runs dnsmasq-rs against a scenario config supplied via a
# scratch disk (see
# docs/superpowers/specs/2026-08-22-dhcp-functional-test-harness-design.md).
#
# Requires sudo: guestfish's supermin helper VM needs to read the host
# kernel image to build its own appliance, and that image is 0600 root:root
# on this class of host -- the same reason setup-host.sh needs sudo, just
# encountered here instead of in network setup.
#
# Safe to re-run: always rebuilds functional/.cache/router.img fresh from
# the pristine base image fetch-openwrt.sh downloaded, so a previous
# customization attempt never lingers half-applied.

if [[ $EUID -ne 0 ]]; then
  echo "build-router-image.sh must be run with sudo (guestfish needs to read the host kernel)." >&2
  exit 1
fi

# The user who invoked sudo -- the output image is chowned back to them so
# a later, unprivileged run.sh can read/copy it without needing sudo itself.
REAL_USER="${SUDO_USER:-$(id -un)}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CACHE_DIR="$ROOT_DIR/functional/.cache"
ROUTER_IMG="$CACHE_DIR/router.img"

log() { echo "==> $*"; }

log "fetching base image (no-op if already cached)"
BASE_IMG="$(sudo -u "$REAL_USER" "$ROOT_DIR/functional/images/fetch-openwrt.sh" | tail -1)"

log "cross-compiling dnsmasq-rs for x86_64-unknown-linux-musl (release)"
# `sudo -u` drops back to the invoking (non-root) user for the build, so
# target/ doesn't end up with root-owned files that later trip up the
# user's own cargo commands -- but sudo resets the environment by default,
# so PATH won't have rustup's shims unless sourced explicitly first.
sudo -u "$REAL_USER" bash -c "
  [ -f \"\$HOME/.cargo/env\" ] && . \"\$HOME/.cargo/env\"
  cd '$ROOT_DIR' && cargo build --release --target x86_64-unknown-linux-musl --bin dnsmasq-rs
"
BINARY="$ROOT_DIR/target/x86_64-unknown-linux-musl/release/dnsmasq-rs"
if [[ ! -x "$BINARY" ]]; then
  echo "expected binary not found at $BINARY" >&2
  exit 1
fi

log "copying base image to $ROUTER_IMG for customization"
cp -f "$BASE_IMG" "$ROUTER_IMG"

# sda2 is the rootfs (sda1 is the small boot/kernel partition) -- confirmed
# by inspecting the OpenWrt 25.12.5 x86-64 generic-ext4-combined image
# (/etc/init.d/dnsmasq, /etc/rc.d/, etc. all live under sda2).
log "customizing $ROUTER_IMG via guestfish"
guestfish -a "$ROUTER_IMG" -m /dev/sda2 <<GUESTFISH
upload $BINARY /usr/sbin/dnsmasq-rs
chmod 0755 /usr/sbin/dnsmasq-rs

# Disable OpenWrt's own dnsmasq (S19dnsmasq is the rc.d startup symlink) so
# it doesn't fight dnsmasq-rs over ports 53/67. This is the offline
# equivalent of running \`/etc/init.d/dnsmasq disable\` -- that command
# just removes this same symlink at boot time.
rm-f /etc/rc.d/S19dnsmasq

upload $ROOT_DIR/functional/images/dnsmasq-rs.init /etc/init.d/dnsmasq-rs
chmod 0755 /etc/init.d/dnsmasq-rs
ln-sf ../init.d/dnsmasq-rs /etc/rc.d/S19dnsmasq-rs
GUESTFISH

chown "$REAL_USER" "$ROUTER_IMG"

log "built $ROUTER_IMG"
echo "$ROUTER_IMG"
