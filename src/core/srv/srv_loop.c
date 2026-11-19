/*
 * Lagoon - SMB2 server: the network loop. One task, several clients: wait
 * on every socket with ln_net_poll(), read what has arrived, hand complete
 * messages to ln_srv_conn_input() and send its reply. TCP 445 (direct SMB),
 * optionally TCP 139 (NetBIOS session service), UDP 137 (NetBIOS names) and
 * UDP 5353 (mDNS). A client that goes away or misbehaves is dropped; the
 * others carry on.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "srv_int.h"

#define MAX_CLIENTS 16

typedef struct Client {
	LnSock *s;
	LnSrvConn *c;
	u8 *rx;
	size_t rxlen, rxcap;
	int nbt;                 /* came in on the NetBIOS session port */
	char peer[48];
} Client;

static void drop(LnSrv *s, Client *cl, const char *why)
{
	LN_LOG(1, "server: %s disconnected%s%s", cl->peer, why ? ": " : "", why ? why : "");
	ln_srv_conn_free(cl->c);
	ln_sock_close(cl->s);
	ln_free(cl->rx);
	memset(cl, 0, sizeof(*cl));
	(void)s;
}

/* handle what is in cl->rx; 0 = ok, <0 = drop */
static int frames(LnSrv *s, Client *cl, size_t maxframe)
{
	while (cl->rxlen >= 4) {
		u8 type = cl->rx[0];
		size_t flen;
		const u8 *out;
		size_t olen;
		int r;
		if (cl->nbt)
			flen = ((size_t)(cl->rx[1] & 1) << 16) | ((size_t)cl->rx[2] << 8) | cl->rx[3];
		else {
			if (type != 0)
				return LN_EPROTO;
			flen = ((size_t)cl->rx[1] << 16) | ((size_t)cl->rx[2] << 8) | cl->rx[3];
		}
		if (flen > maxframe)
			return LN_EPROTO;
		if (cl->rxlen < 4 + flen) {
			if (4 + flen > cl->rxcap) {
				u8 *nb = ln_realloc(cl->rx, cl->rxcap, 4 + flen);
				if (!nb)
					return LN_ENOMEM;
				cl->rx = nb;
				cl->rxcap = 4 + flen;
			}
			return LN_OK;
		}
		if (type == 0x81) {                  /* NetBIOS session request: accept any name */
			static const u8 ok[4] = { 0x82, 0, 0, 0 };
			r = ln_tcp_send(cl->s, ok, 4, 30000);
		} else if (type == 0x85) {           /* keep-alive */
			r = LN_OK;
		} else if (type == 0) {
			r = ln_srv_conn_input(cl->c, cl->rx + 4, flen, &out, &olen);
			if (r == LN_OK && olen)
				r = ln_tcp_send(cl->s, out, olen, 30000);
		} else
			r = LN_EPROTO;
		if (r)
			return r;
		memmove(cl->rx, cl->rx + 4 + flen, cl->rxlen - 4 - flen);
		cl->rxlen -= 4 + flen;
	}
	return LN_OK;
}

int ln_srv_serve(LnSrv *s, const LnSrvNet *n, int (*poll_cb)(void *ud), void *ud)
{
	LnSock *lst = NULL, *lnbt = NULL, *unb = NULL, *umd = NULL;
	Client *cl;
	LnSock *arr[4 + MAX_CLIENTS];
	u8 ready[4 + MAX_CLIENTS];
	u8 *pkt = NULL, *ans = NULL;
	LnAddr me, grp;
	int maxc = s->cfg.max_conns < MAX_CLIENTS ? s->cfg.max_conns : MAX_CLIENTS;
	int r, i, rc = LN_OK, idle = n->idle_minutes > 0 ? n->idle_minutes : 20;
	u16 port = n->port ? n->port : 445;
	size_t maxframe = s->cfg.max_io + 4096;
	u32 last_announce = 0;
	int announces = 0;

	cl = ln_alloc(sizeof(Client) * MAX_CLIENTS);
	pkt = ln_alloc(1500);
	ans = ln_alloc(1500);
	if (!cl || !pkt || !ans) {
		rc = LN_ENOMEM;
		goto out;
	}
	r = ln_tcp_listen(port, &lst);
	if (r) {
		LN_LOG(0, "server: cannot listen on TCP port %u: %s", port, ln_strerror(r));
		rc = r;
		goto out;
	}
	if (n->nbt_port && (r = ln_tcp_listen(n->nbt_port, &lnbt)) != LN_OK)
		LN_LOG(1, "server: no NetBIOS sessions on port %u: %s", n->nbt_port, ln_strerror(r));
	if (ln_local_addr(&me) != LN_OK) {
		memset(&me, 0, sizeof(me));
		me.family = 4;
	}
	if (n->nbns_port) {
		if ((r = ln_udp_open(n->nbns_port, NULL, &unb)) != LN_OK)
			LN_LOG(1, "server: no NetBIOS name service on port %u: %s", n->nbns_port, ln_strerror(r));
		else
			ln_udp_broadcast(unb, 1);
	}
	memset(&grp, 0, sizeof(grp));
	grp.family = 4;
	grp.a[0] = 224; grp.a[3] = 251;
	grp.port = n->mdns_port;
	if (n->mdns_port && (r = ln_udp_open(n->mdns_port, &grp, &umd)) != LN_OK)
		LN_LOG(1, "server: no mDNS on port %u: %s", n->mdns_port, ln_strerror(r));
	{
		char a[48];
		ln_addr_str(&me, a, sizeof(a));
		LN_LOG(1, "server: %s (%s) serving %d share%s on port %u%s%s", s->cfg.name, a, s->nshares,
		       s->nshares == 1 ? "" : "s", port, unb ? ", NetBIOS names" : "", umd ? ", mDNS" : "");
	}

	for (;;) {
		int cnt = 4, k;
		arr[0] = lst; arr[1] = lnbt; arr[2] = unb; arr[3] = umd;
		for (i = 0; i < MAX_CLIENTS; i++)
			arr[cnt++] = cl[i].s;
		/* mDNS announcements: at start, after 1 s and 3 s (RFC 6762 8.3) */
		if (umd && announces < 3 && ln_ms() - last_announce >= (u32)(1000 << announces)) {
			int l = ln_srv_mdns_announce(s, &me, port, ans, 1500);
			if (l > 0)
				ln_udp_sendto(umd, &grp, ans, (size_t)l);
			last_announce = ln_ms();
			announces++;
		}
		r = ln_net_poll(arr, cnt, ready, 1000);
		if (r == LN_EBREAK) {
			rc = LN_EBREAK;
			break;
		}
		if (poll_cb && (k = poll_cb(ud)) != 0) {
			rc = k;
			break;
		}
		if (r < 0)
			continue;
		for (k = 0; k < 2; k++) {
			LnSock *ns;
			LnAddr peer;
			if (!ready[k] || ln_tcp_accept(arr[k], &ns, &peer) != LN_OK)
				continue;
			for (i = 0; i < maxc; i++)
				if (!cl[i].s)
					break;
			if (i == maxc) {
				LN_LOG(0, "server: too many clients, refusing one");
				ln_sock_close(ns);
				continue;
			}
			memset(&cl[i], 0, sizeof(Client));
			ln_addr_str(&peer, cl[i].peer, sizeof(cl[i].peer));
			cl[i].c = ln_srv_conn_new(s, cl[i].peer);
			cl[i].rx = ln_alloc(2048);
			cl[i].rxcap = 2048;
			cl[i].nbt = k == 1;
			if (!cl[i].c || !cl[i].rx) {
				ln_srv_conn_free(cl[i].c);
				ln_free(cl[i].rx);
				ln_sock_close(ns);
				memset(&cl[i], 0, sizeof(Client));
				continue;
			}
			cl[i].s = ns;
			LN_LOG(1, "server: connection from %s", cl[i].peer);
		}
		if (ready[2]) {
			LnAddr from;
			int l = ln_udp_recvfrom(unb, &from, pkt, 1500, 1);
			if (l > 0 && (l = ln_srv_nbns_answer(s, &me, pkt, (size_t)l, ans, 1500)) > 0)
				ln_udp_sendto(unb, &from, ans, (size_t)l);
		}
		if (ready[3]) {
			LnAddr from;
			int l = ln_udp_recvfrom(umd, &from, pkt, 1500, 1), uni = 0;
			if (l > 0 && (l = ln_srv_mdns_answer(s, &me, port, pkt, (size_t)l, from.port == n->mdns_port, ans, 1500, &uni)) > 0)
				ln_udp_sendto(umd, uni ? &from : &grp, ans, (size_t)l);
		}
		for (i = 0; i < MAX_CLIENTS; i++) {
			Client *c = &cl[i];
			if (!c->s)
				continue;
			if (ready[4 + i]) {
				int got = ln_tcp_recv_some(c->s, c->rx + c->rxlen, c->rxcap - c->rxlen, 1000);
				if (got <= 0) {
					drop(s, c, got == 0 ? NULL : ln_strerror(got));
					continue;
				}
				c->rxlen += (size_t)got;
				if ((r = frames(s, c, maxframe)) != LN_OK) {
					drop(s, c, ln_strerror(r));
					continue;
				}
				if (c->rxlen == c->rxcap) {
					/* frames() grows the buffer for a long message; this cannot happen */
					drop(s, c, "receive buffer full");
					continue;
				}
			} else if (!c->c->nopens && ln_ms() - c->c->last_ms > (u32)idle * 60000u) {
				drop(s, c, "idle");
			}
		}
	}
	LN_LOG(1, "server: stopping");
out:
	if (cl) {
		for (i = 0; i < MAX_CLIENTS; i++)
			if (cl[i].s)
				drop(s, &cl[i], "server stopping");
		ln_free(cl);
	}
	ln_sock_close(lst);
	ln_sock_close(lnbt);
	ln_sock_close(unb);
	ln_sock_close(umd);
	ln_free(pkt);
	ln_free(ans);
	return rc;
}
