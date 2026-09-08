/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  iproute2 support for SRv6 L2 tunnel device (sr6)
 *
 *  Usage:
 *    ip link add sr6-0 type sr6 mode full segs fc00::a,fc00::b
 *    ip link add sr6-0 type sr6 mode reduced segs fc00::a,fc00::b
 *    ip link add sr6-0 type sr6 mode full segs fc00::a,fc00::b hmac 1
 *    ip link add sr6-0 type sr6 mode full
 *    ip link set sr6-0 up
 *    ip link set sr6-0 master br0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/seg6.h>
#include <linux/seg6_hmac.h>
#include <linux/if_link.h>

#include "libnetlink.h"
#include "utils.h"
#include "ip_common.h"
#include "json_print.h"
#include "rt_names.h"
#include "sr6.h"

/* parse_opt() appends to the request of iplink_parse(). */
#define SR6_REQ_MAXLEN	sizeof(struct iplink_req)

static void print_explain(FILE *f)
{
	fprintf(f,
		"Usage: ... sr6 [ mode MODE ] [ segs SEG1,SEG2,...,SEGn [ hmac KEYID ] ] [ table TABLE_ID ]\n"
		"\n"
		"Where:	MODE := { full | reduced }, required when the device is created\n"
		"	SEGi := IPv6 address (SRv6 SID)\n"
		"	TABLE_ID := FIB table for post-encap routing\n"
		"	KEYID := HMAC key ID (see ip sr hmac)\n"
	);
}

static void explain(void)
{
	print_explain(stderr);
}

static const char *sr6_encap_modes[] = {
	[SR6_ENCAP_MODE_FULL]		= "full",
	[SR6_ENCAP_MODE_REDUCED]	= "reduced",
};

static const char *format_sr6_encap_mode(int mode)
{
	if (mode < 0 || mode >= ARRAY_SIZE(sr6_encap_modes))
		return "<unknown>";

	return sr6_encap_modes[mode];
}

static int read_sr6_encap_mode(const char *mode)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(sr6_encap_modes); i++) {
		if (strcmp(mode, sr6_encap_modes[i]) == 0)
			return i;
	}

	return -1;
}

static int sr6_parse_opt(struct link_util *lu, int argc, char **argv,
			    struct nlmsghdr *n)
{
	bool set_op = (n->nlmsg_type == RTM_NEWLINK &&
		       !(n->nlmsg_flags & NLM_F_CREATE));
	struct ipv6_sr_hdr *srh;
	const char *segs = NULL;
	int table_ok = 0;
	int mode_ok = 0;
	int hmac_ok = 0;
	__u32 hmac = 0;
	int srhlen;
	int ret;

	while (argc > 0) {
		if (strcmp(*argv, "mode") == 0) {
			int mode;

			NEXT_ARG();
			if (mode_ok++)
				duparg2("mode", *argv);
			mode = read_sr6_encap_mode(*argv);
			if (mode < 0)
				invarg("invalid encap mode", *argv);
			addattr8(n, SR6_REQ_MAXLEN, IFLA_SR6_ENCAP_MODE, mode);
		} else if (strcmp(*argv, "segs") == 0) {
			NEXT_ARG();
			if (segs)
				duparg2("segs", *argv);
			segs = *argv;
		} else if (strcmp(*argv, "table") == 0) {
			__u32 table;

			NEXT_ARG();
			if (table_ok++)
				duparg2("table", *argv);
			if (rtnl_rttable_a2n(&table, *argv))
				invarg("invalid table ID", *argv);
			addattr32(n, SR6_REQ_MAXLEN, IFLA_SR6_FIB_TABLE, table);
		} else if (strcmp(*argv, "hmac") == 0) {
			NEXT_ARG();
			if (hmac_ok++)
				duparg2("hmac", *argv);
			if (get_u32(&hmac, *argv, 0))
				invarg("invalid HMAC key ID", *argv);
		} else if (strcmp(*argv, "help") == 0) {
			explain();
			return -1;
		} else {
			fprintf(stderr, "sr6: unknown command \"%s\"?\n",
				*argv);
			explain();
			return -1;
		}
		argc--, argv++;
	}

	/* The mode is required at creation only. A "set" that leaves it out
	 * keeps the mode the device already has.
	 */
	if (!mode_ok && !set_op) {
		fprintf(stderr, "sr6: missing \"mode\" argument\n");
		explain();
		return -1;
	}

	if (!segs) {
		if (hmac_ok) {
			fprintf(stderr, "sr6: \"hmac\" requires \"segs\"\n");
			return -1;
		}
		return 0;
	}

	srh = sr6_parse_srh(segs, hmac);
	if (!srh) {
		fprintf(stderr, "sr6: cannot allocate the SRH\n");
		return -1;
	}

	srhlen = (srh->hdrlen + 1) << 3;
	/* The ip link request buffer is smaller than the largest SRH
	 * sr6_parse_srh() can build, which bridge fdb is able to send.
	 */
	if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(RTA_LENGTH(srhlen)) >
	    SR6_REQ_MAXLEN) {
		free(srh);
		invarg("segment list too long for the ip link request", "segs");
	}

	ret = addattr_l(n, SR6_REQ_MAXLEN, IFLA_SR6_SRH, srh, srhlen);

	free(srh);
	return ret;
}

static void sr6_print_opt(struct link_util *lu, FILE *f,
			     struct rtattr *tb[])
{
	if (!tb)
		return;

	if (tb[IFLA_SR6_ENCAP_MODE])
		print_string(PRINT_ANY, "mode", "mode %s ",
			     format_sr6_encap_mode(
				rta_getattr_u8(tb[IFLA_SR6_ENCAP_MODE])));

	if (tb[IFLA_SR6_SRH] && sr6_print_srh(tb[IFLA_SR6_SRH])) {
		struct ipv6_sr_hdr *srh = RTA_DATA(tb[IFLA_SR6_SRH]);

		if (sr_has_hmac(srh)) {
			struct sr6_tlv_hmac *tlv;
			unsigned int offset = ((srh->hdrlen + 1) << 3) -
					      sizeof(*tlv);

			tlv = (struct sr6_tlv_hmac *)((char *)srh + offset);
			print_0xhex(PRINT_ANY, "hmac",
				    "hmac %llX ", ntohl(tlv->hmackeyid));
		}
	}

	if (tb[IFLA_SR6_FIB_TABLE])
		print_uint(PRINT_ANY, "table", "table %u ",
			   rta_getattr_u32(tb[IFLA_SR6_FIB_TABLE]));
}

static void sr6_print_help(struct link_util *lu, int argc, char **argv,
			      FILE *f)
{
	print_explain(f);
}

struct link_util sr6_link_util = {
	.id		= "sr6",
	.maxattr	= IFLA_SR6_MAX,
	.parse_opt	= sr6_parse_opt,
	.print_opt	= sr6_print_opt,
	.print_help	= sr6_print_help,
};
