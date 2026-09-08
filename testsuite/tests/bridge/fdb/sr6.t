#!/bin/sh
# SPDX-License-Identifier: GPL-2.0

. lib/generic.sh

ts_log "[Testing sr6 FDB policies]"

DEV="$(rand_dev)"
MAC=02:00:00:00:00:01
SEGS=fc00::a,fc00::b

# Requires a kernel with the experimental sr6 FDB UAPI.
if ! "$IP" link add dev "$DEV" type sr6 mode full 2>"$STD_ERR"; then
	if grep -q 'Unknown device type\|Operation not supported' "$STD_ERR"; then
		ts_skip
	fi
	ts_err_cat "$STD_ERR"
	exit 1
fi
trap '"$IP" link del dev "$DEV"' EXIT

expect_fail()
{
	desc=$1
	shift
	if "$@" >"$STD_OUT" 2>"$STD_ERR"; then
		ts_err "$desc unexpectedly succeeded"
	fi
}

ts_ip "$0" "Show FDB-only device" -d link show dev "$DEV"
test_on 'mode full'

ts_bridge "$0" "Add permanent policy" fdb add "$MAC" dev "$DEV" segs "$SEGS"
ts_bridge "$0" "Show policy" fdb show dev "$DEV"
test_on "segs $SEGS"
test_on "self permanent"
ts_bridge "$0" "Get policy as JSON" -j fdb get "$MAC" dev "$DEV" self
test_on '"segs":\["fc00::a","fc00::b"\]'

expect_fail "Duplicate add" "$BRIDGE" fdb add "$MAC" dev "$DEV" segs "$SEGS"
expect_fail "Missing SRH" "$BRIDGE" fdb replace "$MAC" dev "$DEV"
expect_fail "Mismatched delete" "$BRIDGE" fdb del "$MAC" dev "$DEV" segs fc00::c
ts_bridge "$0" "Policy survives failed operations" fdb get "$MAC" dev "$DEV" self
test_on "segs $SEGS"

ts_bridge "$0" "Replace with static policy" fdb replace "$MAC" dev "$DEV" static segs fc00::c
ts_bridge "$0" "Get replaced policy" fdb get "$MAC" dev "$DEV" self
test_on 'segs fc00::c'
test_on 'self static'
ts_bridge "$0" "Delete matching policy" fdb del "$MAC" dev "$DEV" segs fc00::c
expect_fail "Get deleted policy" "$BRIDGE" fdb get "$MAC" dev "$DEV" self

# This policy exceeds the old 256-byte FDB request buffer and exercises the
# largest segment list representable by the SRH hdrlen field.
LONG_SEGS=$(awk 'BEGIN { for (i = 1; i <= 127; i++) printf "%sfc00::%x", i == 1 ? "" : ",", i }')
ts_bridge "$0" "Replace creates absent policy" fdb replace "$MAC" dev "$DEV" segs "$LONG_SEGS"
ts_bridge "$0" "Show maximum length policy" fdb show dev "$DEV"
test_on "segs $LONG_SEGS"
ts_bridge "$0" "Delete by MAC" fdb del "$MAC" dev "$DEV"
ts_bridge "$0" "Empty table" fdb show dev "$DEV"
test_lines_count 0

for segs in '' ,fc00::a fc00::a, fc00::a,,fc00::b 192.0.2.1 fc00::a/64 "$LONG_SEGS,fc00::80"; do
	expect_fail "Invalid segment list $segs" "$BRIDGE" fdb add "$MAC" dev "$DEV" segs "$segs"
done
expect_fail "Duplicate segs" "$BRIDGE" fdb add "$MAC" dev "$DEV" segs fc00::a segs fc00::b
expect_fail "Append policy" "$BRIDGE" fdb append "$MAC" dev "$DEV" segs fc00::a
expect_fail "VLAN policy" "$BRIDGE" fdb add "$MAC" dev "$DEV" vlan 1 segs fc00::a
expect_fail "Remote policy" "$BRIDGE" fdb add "$MAC" dev "$DEV" dst fc00::b segs fc00::a
expect_fail "Master policy" "$BRIDGE" fdb add "$MAC" dev "$DEV" master segs fc00::a
expect_fail "Multicast MAC" "$BRIDGE" fdb add 01:00:00:00:00:01 dev "$DEV" segs fc00::a

# The interface-level fallback remains usable alongside per-MAC policies.
ts_ip "$0" "Delete FDB-only device" link del dev "$DEV"
ts_ip "$0" "Create device with fallback" link add dev "$DEV" type sr6 mode full segs "$SEGS"
ts_ip "$0" "Show fallback" -d link show dev "$DEV"
test_on "segs $SEGS"
ts_bridge "$0" "Add policy alongside fallback" fdb add "$MAC" dev "$DEV" segs fc00::c
ts_bridge "$0" "Get policy alongside fallback" fdb get "$MAC" dev "$DEV" self
test_on 'segs fc00::c'

# New sr6 options must continue to work with the shared SRH parser.
ts_ip "$0" "Delete full-mode device" link del dev "$DEV"
ts_ip "$0" "Create reduced device with HMAC and table" link add dev "$DEV" type sr6 mode reduced segs "$SEGS" hmac 1 table 100
ts_ip "$0" "Show reduced fallback" -d link show dev "$DEV"
test_on 'mode reduced'
test_on "segs $SEGS"
test_on 'hmac 0x1'
test_on 'table 100'
ts_bridge "$0" "Add reduced-mode policy" fdb add "$MAC" dev "$DEV" segs fc00::c
ts_bridge "$0" "Get reduced-mode policy" fdb get "$MAC" dev "$DEV" self
test_on 'segs fc00::c'
