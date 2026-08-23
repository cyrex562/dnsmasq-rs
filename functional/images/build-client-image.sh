#!/usr/bin/env bash
set -euo pipefail

# Customizes the fetched Alpine base image into the client VM image
# functional/lib/client.sh boots: disables the image's own default-runlevel
# services (networking, tiny-cloud-*, sshd, chronyd -- none of which this
# harness needs, and "networking" would otherwise race our own manual
# udhcpc run on eth0) and installs one custom OpenRC service that runs a
# single DHCP transaction and reports the result (see
# docs/superpowers/specs/2026-08-23-dhcp-harness-vm-client-design.md).
#
# Requires sudo: guestfish's supermin helper VM needs to read the host
# kernel image, the same reason build-router-image.sh needs it.
#
# Safe to re-run: always rebuilds functional/.cache/client.img fresh from
# the pristine base image fetch-alpine.sh downloaded.

if [[ $EUID -ne 0 ]]; then
  echo "build-client-image.sh must be run with sudo (guestfish needs to read the host kernel)." >&2
  exit 1
fi

REAL_USER="${SUDO_USER:-$(id -un)}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CACHE_DIR="$ROOT_DIR/functional/.cache"
CLIENT_IMG="$CACHE_DIR/client.img"

log() { echo "==> $*"; }

log "fetching base image (no-op if already cached)"
BASE_IMG="$(sudo -u "$REAL_USER" "$ROOT_DIR/functional/images/fetch-alpine.sh" | tail -1)"

log "copying base image to $CLIENT_IMG for customization"
cp -f "$BASE_IMG" "$CLIENT_IMG"

# The image has a single ext4 filesystem directly on sda (no partition
# table, unlike OpenWrt's sda1/sda2 router image) -- confirmed by
# inspecting the Alpine 3.24.1 generic_alpine-*-bios-tiny-r0 image via
# `guestfish --ro ... list-filesystems`.
log "customizing $CLIENT_IMG via guestfish"
guestfish -a "$CLIENT_IMG" -m /dev/sda <<GUESTFISH
upload $ROOT_DIR/functional/images/client-dhcp-test.init /etc/init.d/dhcp-test-client
chmod 0755 /etc/init.d/dhcp-test-client

# upload doesn't create parent directories, and this minimal Alpine image
# doesn't ship /usr/local/sbin -- confirmed the hard way ("upload: ...: No
# such file or directory") on first attempt.
mkdir-p /usr/local/sbin
upload $ROOT_DIR/functional/images/client-udhcpc-handler.sh /usr/local/sbin/dhcp-test-handler.sh
chmod 0755 /usr/local/sbin/dhcp-test-handler.sh

# Disable every default-runlevel service this image ships with: "networking"
# would bring up its own DHCP client on eth0 and race our own; the
# tiny-cloud-* services would otherwise spend boot time looking for a
# cloud-init datasource that doesn't exist here; sshd/chronyd aren't needed
# for a single DHCP transaction. This is the offline equivalent of
# \`rc-update del <service> default\` for each.
rm-f /etc/runlevels/default/networking
rm-f /etc/runlevels/default/tiny-cloud-early
rm-f /etc/runlevels/default/tiny-cloud-final
rm-f /etc/runlevels/default/tiny-cloud-main
rm-f /etc/runlevels/default/sshd
rm-f /etc/runlevels/default/chronyd

# Two levels of ".." because /etc/runlevels/default/ is two directories
# below /etc/, not one -- unlike OpenWrt's flat /etc/rc.d/ (one level
# below /etc/), where the router image's equivalent symlink only needs a
# single "..". Confirmed the hard way: the first attempt's symlink was
# valid but pointed at the non-existent /etc/runlevels/init.d/..., so
# OpenRC's default runlevel had nothing to run even though \`rc default\`
# itself executes unconditionally from /etc/inittab.
ln-sf ../../init.d/dhcp-test-client /etc/runlevels/default/dhcp-test-client
GUESTFISH

# The base image is qcow2; guestfish edits it in place without changing
# its format. Convert to raw so vm.sh's shared start_vm (used by both the
# router and every client VM) can assume every image drive is
# format=raw, matching the OpenWrt router image's native format.
log "converting to raw format for QEMU boot"
qemu-img convert -O raw "$CLIENT_IMG" "$CLIENT_IMG.raw"
mv -f "$CLIENT_IMG.raw" "$CLIENT_IMG"

chown "$REAL_USER" "$CLIENT_IMG"

log "built $CLIENT_IMG"
echo "$CLIENT_IMG"
