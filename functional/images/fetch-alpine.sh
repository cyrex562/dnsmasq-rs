#!/usr/bin/env bash
set -euo pipefail

# Downloads and verifies the pinned Alpine x86_64 cloud image the functional
# harness's client VMs boot. Safe to re-run: skips the download if the
# image already exists.
#
# The image lives under functional/.cache/ (gitignored) — it does not
# belong in git, the same reasoning fetch-openwrt.sh documents for the
# router image.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CACHE_DIR="$ROOT_DIR/functional/.cache"

ALPINE_VERSION=3.24.1
ALPINE_BRANCH=v3.24
IMAGE_BASENAME="generic_alpine-${ALPINE_VERSION}-x86_64-bios-tiny-r0.qcow2"
IMAGE_URL="https://dl-cdn.alpinelinux.org/alpine/${ALPINE_BRANCH}/releases/cloud/${IMAGE_BASENAME}"
# From https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/cloud/generic_alpine-3.24.1-x86_64-bios-tiny-r0.qcow2.sha512
# -- pinned so a tampered or corrupted download is caught rather than
# silently used.
EXPECTED_SHA512=c245c259397defd353095ee4416a1e4cffdb68aa57e5c8bb1bf06f019322c4f72eca9b1c6372e1ee1432bd4fa83669863e28f13817915387b743ea3782e3327e

log() { echo "==> $*"; }

mkdir -p "$CACHE_DIR"
cd "$CACHE_DIR"

IMG_PATH="$CACHE_DIR/$IMAGE_BASENAME"

if [[ -f "$IMG_PATH" ]]; then
  log "already have $IMAGE_BASENAME, skipping download"
  echo "$IMG_PATH"
  exit 0
fi

log "downloading $IMAGE_BASENAME (Alpine $ALPINE_VERSION)"
curl -fL --progress-bar -o "$IMG_PATH" "$IMAGE_URL"

log "verifying checksum"
ACTUAL_SHA512=$(sha512sum "$IMG_PATH" | cut -d' ' -f1)
if [[ "$ACTUAL_SHA512" != "$EXPECTED_SHA512" ]]; then
  echo "checksum mismatch for $IMG_PATH:" >&2
  echo "  expected: $EXPECTED_SHA512" >&2
  echo "  actual:   $ACTUAL_SHA512" >&2
  rm -f "$IMG_PATH"
  exit 1
fi

log "fetched $IMG_PATH"
echo "$IMG_PATH"
