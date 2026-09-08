#!/bin/sh
# SPDX-License-Identifier: GPL-2.0

. lib/generic.sh

ts_log "[Testing sr6 FDB policies]"

DEV="$(rand_dev)"
ZERO=00:00:00:00:00:00
MAC=02:00:00:00:00:01
SEGS=fc00::a,fc00::b

# Requires a kernel with the experimental sr6 FDB UAPI.
if ! "$IP" link add dev "$DEV" type sr6 2>"$STD_ERR"; then
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
test_on 'sr6 addrgenmode'
ts_bridge "$0" "Empty FDB" fdb show dev "$DEV"
test_lines_count 0

# Unicast entries hold one remote each.
ts_bridge "$0" "Add permanent policy" fdb add "$MAC" dev "$DEV" segs "$SEGS"
ts_bridge "$0" "Show policy" fdb show dev "$DEV"
test_on "segs $SEGS mode full self permanent"
ts_bridge "$0" "Get policy as JSON" -j fdb get "$MAC" dev "$DEV" self
test_on '"segs":\["fc00::a","fc00::b"\],"mode":"full"'

expect_fail "Duplicate add" "$BRIDGE" fdb add "$MAC" dev "$DEV" segs "$SEGS"
expect_fail "Missing SRH" "$BRIDGE" fdb replace "$MAC" dev "$DEV"
expect_fail "Mismatched delete" "$BRIDGE" fdb del "$MAC" dev "$DEV" segs fc00::c
expect_fail "Append to unicast entry" "$BRIDGE" fdb append "$MAC" dev "$DEV" segs fc00::c
ts_bridge "$0" "Policy survives failed operations" fdb get "$MAC" dev "$DEV" self
test_on "segs $SEGS mode full"

ts_bridge "$0" "Replace with static reduced policy" fdb replace "$MAC" dev "$DEV" static segs fc00::c mode reduced table 100
ts_bridge "$0" "Get replaced policy" fdb get "$MAC" dev "$DEV" self
test_on 'segs fc00::c mode reduced table 100 self static'
ts_bridge "$0" "Get replaced policy as JSON" -j fdb get "$MAC" dev "$DEV" self
test_on '"mode":"reduced","table":100'
expect_fail "Delete without matching table" "$BRIDGE" fdb del "$MAC" dev "$DEV" segs fc00::c
ts_bridge "$0" "Delete matching policy" fdb del "$MAC" dev "$DEV" segs fc00::c table 100
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

# The all-zeros entry holds several remotes.
ts_bridge "$0" "Add flood remote" fdb add "$ZERO" dev "$DEV" self permanent segs fc00:2::d20
ts_ip "$0" "Link reports single flood remote" -d link show dev "$DEV"
test_on 'mode full segs fc00:2::d20'
ts_bridge "$0" "Append flood remote" fdb append "$ZERO" dev "$DEV" self permanent segs fc00:3::d20 mode reduced
ts_bridge "$0" "Append flood remote with table" fdb append "$ZERO" dev "$DEV" segs fc00:3::d20 table 200
expect_fail "Append existing remote" "$BRIDGE" fdb append "$ZERO" dev "$DEV" segs fc00:3::d20
ts_bridge "$0" "Show flood remotes" fdb show dev "$DEV"
test_lines_count 3
test_on "$ZERO segs fc00:2::d20 mode full self permanent"
test_on "$ZERO segs fc00:3::d20 mode reduced self permanent"
test_on "$ZERO segs fc00:3::d20 mode full table 200 self permanent"
ts_ip "$0" "Link omits several flood remotes" -d link show dev "$DEV"
test_on 'sr6 addrgenmode'
expect_fail "ip link change with several remotes" "$IP" link set dev "$DEV" type sr6 segs fc00::1

expect_fail "Ambiguous replace" "$BRIDGE" fdb replace "$ZERO" dev "$DEV" segs fc00:4::d20
expect_fail "Old segs without replace" "$BRIDGE" fdb add "$ZERO" dev "$DEV" segs fc00:4::d20 old segs fc00:2::d20
expect_fail "Replace of absent remote" "$BRIDGE" fdb replace "$ZERO" dev "$DEV" segs fc00:4::d20 old segs fc00:5::d20
ts_bridge "$0" "Replace selected remote" fdb replace "$ZERO" dev "$DEV" segs fc00:4::d20 old segs fc00:3::d20
ts_bridge "$0" "Replace remote selected with table" fdb replace "$ZERO" dev "$DEV" segs fc00:5::d20 mode reduced old segs fc00:3::d20 old table 200
ts_bridge "$0" "Show replaced flood remotes" fdb show dev "$DEV"
test_lines_count 3
test_on "segs fc00:4::d20 mode full self"
test_on "segs fc00:5::d20 mode reduced self"

ts_bridge "$0" "Delete one flood remote" fdb del "$ZERO" dev "$DEV" segs fc00:2::d20
ts_bridge "$0" "Show remaining flood remotes" fdb show dev "$DEV"
test_lines_count 2
ts_bridge "$0" "Delete flood entry" fdb del "$ZERO" dev "$DEV"
ts_bridge "$0" "Empty table after flood entry" fdb show dev "$DEV"
test_lines_count 0

for segs in '' ,fc00::a fc00::a, fc00::a,,fc00::b 192.0.2.1 fc00::a/64 "$LONG_SEGS,fc00::80"; do
	expect_fail "Invalid segment list $segs" "$BRIDGE" fdb add "$MAC" dev "$DEV" segs "$segs"
done
expect_fail "Duplicate segs" "$BRIDGE" fdb add "$MAC" dev "$DEV" segs fc00::a segs fc00::b
expect_fail "Invalid mode" "$BRIDGE" fdb add "$MAC" dev "$DEV" segs fc00::a mode foo
expect_fail "Mode without segs" "$BRIDGE" fdb add "$MAC" dev "$DEV" mode full
expect_fail "Table without segs" "$BRIDGE" fdb add "$MAC" dev "$DEV" table 100
expect_fail "Old table without old segs" "$BRIDGE" fdb replace "$ZERO" dev "$DEV" segs fc00::a old table 100
expect_fail "VLAN policy" "$BRIDGE" fdb add "$MAC" dev "$DEV" vlan 1 segs fc00::a
expect_fail "Remote policy" "$BRIDGE" fdb add "$MAC" dev "$DEV" dst fc00::b segs fc00::a
expect_fail "Master policy" "$BRIDGE" fdb add "$MAC" dev "$DEV" master segs fc00::a
expect_fail "Multicast MAC" "$BRIDGE" fdb add 01:00:00:00:00:01 dev "$DEV" segs fc00::a

expect_fail "Mode without segs on link" "$IP" link set dev "$DEV" type sr6 mode reduced
expect_fail "Table without segs on link" "$IP" link set dev "$DEV" type sr6 table 100

# ip link configures the only remote of the all-zeros entry.
ts_ip "$0" "Delete FDB-only device" link del dev "$DEV"
ts_ip "$0" "Create device with flood remote" link add dev "$DEV" type sr6 segs "$SEGS"
ts_ip "$0" "Show flood remote" -d link show dev "$DEV"
test_on "mode full segs $SEGS"
ts_bridge "$0" "FDB shows link policy" fdb show dev "$DEV"
test_on "$ZERO segs $SEGS mode full self permanent"
ts_bridge "$0" "Add policy alongside flood remote" fdb add "$MAC" dev "$DEV" segs fc00::c
ts_bridge "$0" "Get policy alongside flood remote" fdb get "$MAC" dev "$DEV" self
test_on 'segs fc00::c'
ts_ip "$0" "Change link policy" link set dev "$DEV" type sr6 segs fc00::d mode reduced table 100
ts_ip "$0" "Keep mode and table on link change" link set dev "$DEV" type sr6 segs fc00::e
ts_ip "$0" "Show changed flood remote" -d link show dev "$DEV"
test_on 'mode reduced segs fc00::e table 100'

# The sr6 link options must continue to work with the shared SRH parser.
ts_ip "$0" "Delete device" link del dev "$DEV"
ts_ip "$0" "Create reduced device with HMAC and table" link add dev "$DEV" type sr6 mode reduced segs "$SEGS" hmac 1 table 100
ts_ip "$0" "Show reduced flood remote" -d link show dev "$DEV"
test_on "mode reduced segs $SEGS hmac 1 table 100"
