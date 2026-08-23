#!/usr/bin/env bash
set -euo pipefail

# Downloads and verifies the pinned OpenWrt x86_64 image the functional
# harness's router VM boots. Safe to re-run: skips the download if the
# decompressed image already exists with the expected checksum.
#
# The image lives under functional/.cache/ (gitignored) — it does not belong
# in git, the same reasoning that kept the Docker build context in parity/
# from including the repo's own target/ directory.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CACHE_DIR="$ROOT_DIR/functional/.cache"

OPENWRT_VERSION=25.12.5
IMAGE_BASENAME="openwrt-${OPENWRT_VERSION}-x86-64-generic-ext4-combined.img"
IMAGE_URL="https://downloads.openwrt.org/releases/${OPENWRT_VERSION}/targets/x86/64/${IMAGE_BASENAME}.gz"
# From https://downloads.openwrt.org/releases/25.12.5/targets/x86/64/sha256sums
# for openwrt-25.12.5-x86-64-generic-ext4-combined.img.gz — pinned so a
# tampered or corrupted download is caught rather than silently used.
EXPECTED_GZ_SHA256=23e2538e8ab0eb52dfed1c65d608ecdb71ffd432dd54885da138ae67cd9e4461

log() { echo "==> $*"; }

mkdir -p "$CACHE_DIR"
cd "$CACHE_DIR"

IMG_PATH="$CACHE_DIR/$IMAGE_BASENAME"
GZ_PATH="$IMG_PATH.gz"

if [[ -f "$IMG_PATH" ]]; then
  log "already have $IMAGE_BASENAME, skipping download"
  echo "$IMG_PATH"
  exit 0
fi

log "downloading $IMAGE_BASENAME (OpenWrt $OPENWRT_VERSION)"
curl -fL --progress-bar -o "$GZ_PATH" "$IMAGE_URL"

log "verifying checksum"
ACTUAL_SHA256=$(sha256sum "$GZ_PATH" | cut -d' ' -f1)
if [[ "$ACTUAL_SHA256" != "$EXPECTED_GZ_SHA256" ]]; then
  echo "checksum mismatch for $GZ_PATH:" >&2
  echo "  expected: $EXPECTED_GZ_SHA256" >&2
  echo "  actual:   $ACTUAL_SHA256" >&2
  rm -f "$GZ_PATH"
  exit 1
fi

log "decompressing"
gunzip -k "$GZ_PATH"
rm -f "$GZ_PATH"

log "fetched $IMG_PATH"
echo "$IMG_PATH"
