// SPDX-License-Identifier: GPL-2.0

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <linux/seg6_hmac.h>

#include "utils.h"
#include "json_print.h"
#include "sr6.h"

/* Return a malloc'd full SRH template for either encapsulation mode.
 * Reduced encoding is performed by the kernel at transmit time.
 */
struct ipv6_sr_hdr *sr6_parse_srh(const char *segs, __u32 hmac)
{
	struct ipv6_sr_hdr *srh;
	char *buf, *next, *seg;
	const char *p;
	int nsegs = 1, srhlen, i;
	int maxsegs = hmac ? 125 : 127;

	if (!segs || !*segs)
		invarg("missing segment list", "segs");

	for (p = segs; *p; p++) {
		/* hdrlen is an 8-bit count of 8-byte units, excluding
		 * the fixed header. Each segment occupies two units.
		 */
		if (*p == ',' && ++nsegs > maxsegs)
			invarg(hmac ? "too many segments (maximum 125 with HMAC)" :
			       "too many segments (maximum 127)", segs);
	}

	srhlen = sizeof(*srh) + nsegs * sizeof(struct in6_addr);
	if (hmac)
		srhlen += sizeof(struct sr6_tlv_hmac);
	srh = calloc(1, srhlen);
	if (!srh)
		return NULL;
	buf = strdup(segs);
	if (!buf) {
		free(srh);
		return NULL;
	}

	srh->hdrlen = (srhlen >> 3) - 1;
	srh->type = 4;
	srh->segments_left = nsegs - 1;
	srh->first_segment = nsegs - 1;

	/* Command-line order is first hop to final destination. */
	next = buf;
	for (i = nsegs - 1; i >= 0; i--) {
		seg = strsep(&next, ",");
		if (inet_pton(AF_INET6, seg, &srh->segments[i]) != 1)
			invarg("invalid IPv6 segment", seg);
	}
	if (hmac) {
		struct sr6_tlv_hmac *tlv;

		srh->flags |= SR6_FLAG1_HMAC;
		tlv = (struct sr6_tlv_hmac *)((char *)srh + srhlen -
					    sizeof(*tlv));
		tlv->tlvhdr.type = SR6_TLV_HMAC;
		tlv->tlvhdr.len = sizeof(*tlv) - sizeof(tlv->tlvhdr);
		tlv->hmackeyid = htonl(hmac);
	}

	free(buf);
	return srh;
}

bool sr6_print_srh(struct rtattr *attr)
{
	const struct ipv6_sr_hdr *srh = RTA_DATA(attr);
	unsigned int len = RTA_PAYLOAD(attr);
	int i;

	if (len < sizeof(*srh) || srh->type != 4 ||
	    len != (srh->hdrlen + 1U) * 8 ||
	    sizeof(*srh) + (srh->first_segment + 1U) *
			  sizeof(struct in6_addr) +
			  (sr_has_hmac(srh) ? sizeof(struct sr6_tlv_hmac) : 0) > len ||
	    srh->segments_left > srh->first_segment + 1U) {
		fprintf(stderr, "Invalid sr6 SRH\n");
		return false;
	}

	print_string(PRINT_FP, NULL, "segs ", NULL);
	open_json_array(PRINT_JSON, "segs");
	for (i = srh->first_segment; i >= 0; i--) {
		if (i < srh->first_segment)
			print_string(PRINT_FP, NULL, ",", NULL);
		print_color_string(PRINT_ANY, COLOR_INET6, NULL, "%s",
				   rt_addr_n2a(AF_INET6, 16, &srh->segments[i]));
	}
	close_json_array(PRINT_JSON, NULL);
	print_string(PRINT_FP, NULL, " ", NULL);
	return true;
}
