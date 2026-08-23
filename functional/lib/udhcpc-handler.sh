#!/bin/sh
# busybox udhcpc event handler for the DHCP functional test harness.
# Invoked by udhcpc itself as: $0 deconfig|bound|renew|nak|leasefail
# udhcpc exports lease facts (ip, router, dns, lease, ...) as environment
# variables for bound/renew. This normalizes them into a shell-sourceable
# RESULT file that lib/client.sh reads back — network namespaces only
# isolate the network stack, not the filesystem, so both sides see the
# same $RESULT_FILE path directly.

[ -n "$RESULT_FILE" ] || exit 0

case "$1" in
	bound|renew)
		# router/dns can carry multiple space-separated addresses; take
		# the first, both because that's what a real client primarily
		# acts on and because an unquoted multi-word value would corrupt
		# this file's own shell-assignment syntax when client.sh sources
		# it back (`FOO=a b` runs "b" as a command with FOO=a in its
		# environment, leaving the caller's FOO unset).
		{
			echo "RESULT=lease"
			echo "ACTUAL_IP=$ip"
			echo "ACTUAL_ROUTER=${router%% *}"
			echo "ACTUAL_DNS=${dns%% *}"
			echo "ACTUAL_LEASE=$lease"
			echo "ACTUAL_DOMAIN=$domain"
			echo "ACTUAL_NTP=${ntpsrv%% *}"
		} > "$RESULT_FILE"
		;;
	nak)
		echo "RESULT=nak" > "$RESULT_FILE"
		;;
	leasefail)
		echo "RESULT=timeout" > "$RESULT_FILE"
		;;
esac
