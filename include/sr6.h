/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __SR6_H__
#define __SR6_H__

#include <stdbool.h>
#include <linux/seg6.h>
#include <linux/rtnetlink.h>

struct ipv6_sr_hdr *sr6_parse_srh(const char *segs, __u32 hmac);
bool sr6_print_srh(struct rtattr *attr);

#endif
