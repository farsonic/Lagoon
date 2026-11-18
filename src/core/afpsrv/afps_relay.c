/*
 * Lagoon - the AFP server's second node: NBP answers and a relay, for the Mac's AppleShare
 * client (afps.h, "the multinode in front of the server").
 *
 * Backstory. The bridge first registered "<share>:AFPServer@*" on its own ATP socket with the
 * Mac's NBP, and the Chooser and PBVolumeMount found it, but the AppleShare client then refused
 * at once with afpSameNodeErr (-5063, the testbed's log, 18 November 2026): a Mac does not
 * mount its own server. A multinode is the AppleTalk Manager's own answer to "this Mac as
 * another node": .MPP gives it an address and hands its datagrams, and every broadcast, to a
 * receive routine, and loops datagrams between it and the user node without the network. But it
 * has no NBP and no ATP of its own. So the multinode answers NBP lookups for the server's name
 * itself (this file), and passes every other datagram on, rewriting only the DDP addresses, to
 * the server's .ATP socket on the user node and back: ATP, ASP and AFP stay where they were.
 *
 * The relay knows one client node at a time (the last one heard from): the Mac itself, or one
 * other machine. That is the bridge's purpose; a server for a network has better homes.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "afps_int.h"

#define NBP_BRRQ   1
#define NBP_LKUP   2
#define NBP_REPLY  3
#define NBP_ALMOST 0xC5          /* the Mac Roman approximately-equal sign: a wildcard */

static int lower(int c) { return c >= 'A' && c <= 'Z' ? c + 32 : c; }

/* an NBP field against our name: "=", "≈" somewhere, or equal without case */
static int nbp_match(const u8 *pat, size_t n, const char *name)
{
	size_t l = strlen(name), i, w;
	if (n == 1 && pat[0] == '=')
		return 1;
	for (w = 0; w < n && pat[w] != NBP_ALMOST; w++)
		;
	if (w < n) {                                 /* prefix ≈ suffix */
		size_t sfx = n - w - 1;
		if (w + sfx > l)
			return 0;
		for (i = 0; i < w; i++)
			if (lower(pat[i]) != lower((u8)name[i]))
				return 0;
		for (i = 0; i < sfx; i++)
			if (lower(pat[w + 1 + i]) != lower((u8)name[l - sfx + i]))
				return 0;
		return 1;
	}
	if (n != l)
		return 0;
	for (i = 0; i < n; i++)
		if (lower(pat[i]) != lower((u8)name[i]))
			return 0;
	return 1;
}

static void put_pstr(u8 *o, size_t *k, const char *s)
{
	size_t l = strlen(s);
	o[(*k)++] = (u8)l;
	memcpy(o + *k, s, l);
	*k += l;
}

size_t afps_nbp_answer(const u8 *nbp, size_t n, const char *object, const char *type, AsAddr me,
                       u8 *out, size_t max, AsAddr *to)
{
	unsigned fn, cnt;
	const u8 *t, *obj, *typ, *zone;
	size_t k = 0;
	if (n < 2 + 5 + 3)
		return 0;
	fn = nbp[0] >> 4;
	cnt = nbp[0] & 15;
	if ((fn != NBP_LKUP && fn != NBP_BRRQ) || cnt != 1)
		return 0;
	t = nbp + 2;                                 /* the requester's address, then the name */
	obj = t + 5;
	if (obj + 1 + obj[0] >= nbp + n)
		return 0;
	typ = obj + 1 + obj[0];
	if (typ + 1 + typ[0] >= nbp + n)
		return 0;
	zone = typ + 1 + typ[0];
	if (zone + 1 + zone[0] > nbp + n)
		return 0;
	if (!nbp_match(obj + 1, obj[0], object) || !nbp_match(typ + 1, typ[0], type))
		return 0;
	if (max < 2 + 5 + 3 + strlen(object) + strlen(type) + 1)
		return 0;
	to->net = ln_be16(t);
	to->node = t[2];
	to->socket = t[3];
	out[k++] = (u8)(NBP_REPLY << 4 | 1);
	out[k++] = nbp[1];                           /* the lookup's NBP ID */
	ln_put_be16(out + k, me.net);
	out[k + 2] = me.node;
	out[k + 3] = me.socket;
	out[k + 4] = 0;                              /* enumerator */
	k += 5;
	put_pstr(out, &k, object);
	put_pstr(out, &k, type);
	put_pstr(out, &k, "*");
	return k;
}

int afps_relay(AfpsRelay *r, u8 h[13])
{
	u16 dnet = ln_be16(h + 4), snet = ln_be16(h + 6);
	u8 dnode = h[8], snode = h[9], dsock = h[10], ssock = h[11];
	if (dnode != r->vnode.node || (dnet && dnet != r->vnode.net))
		return 0;
	if (dsock == r->vnode.socket) {
		/* a client to the server: it seems to come from the multinode, the client's socket kept */
		r->cnet = snet;
		r->cnode = snode;
		r->have_client = 1;
		ln_put_be16(h + 4, r->server.net);
		h[8] = r->server.node;
		h[10] = r->server.socket;
		ln_put_be16(h + 6, r->vnode.net);
		h[9] = r->vnode.node;
	} else if (r->have_client && snode == r->server.node && ssock == r->server.socket &&
	           (!snet || snet == r->server.net)) {
		/* the server to a client socket: from the multinode's server socket */
		ln_put_be16(h + 4, r->cnet);
		h[8] = r->cnode;
		ln_put_be16(h + 6, r->vnode.net);
		h[9] = r->vnode.node;
		h[11] = r->vnode.socket;
	} else
		return 0;
	h[2] = h[3] = 0;                             /* no checksum: the addresses changed */
	h[0] &= 0x03;                                /* hop count 0: it never left this Mac */
	return 1;
}
