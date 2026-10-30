/* Lagoon - NFS backend unit tests: XDR, AUTH_SYS, RPC call framing, record
 * marking, reply parsing (incl. rejections), fattr3 decoding, status maps.
 * SPDX-License-Identifier: GPL-2.0-only */
#include "testutil.h"
#include "ln_sys.h"
#include "nfs/nfs_rpc.h"

static void xdr(void)
{
	u8 b[64];
	NfsXdr x;
	u32 n;
	const u8 *p;
	char s[8];
	NfsFh fh;
	xdr_init_enc(&x, b, sizeof(b));
	xdr_put_u32(&x, 0x01020304);
	xdr_put_u64(&x, 0x1122334455667788ULL);
	xdr_put_string(&x, "abcde");
	xdr_put_opaque(&x, "", 0);
	CHECK(!x.err);
	CHECK_INT(x.pos, 4 + 8 + 4 + 8 + 4);
	CHECK_HEX(b, x.pos, "01020304112233445566778800000005616263646500000000000000");
	xdr_init_dec(&x, b, 28);
	CHECK_INT(xdr_get_u32(&x), 0x01020304);
	CHECK(xdr_get_u64(&x) == 0x1122334455667788ULL);
	CHECK_INT(xdr_get_string(&x, s, sizeof(s)), LN_OK);
	CHECK_STR(s, "abcde");
	CHECK_INT(x.pos, 24);
	p = xdr_get_opaque(&x, &n, 10);
	CHECK(p != NULL); CHECK_INT(n, 0);
	CHECK(!x.err);
	xdr_get_u32(&x);
	CHECK(x.err);                    /* past the end */
	/* string too long for the buffer: skipped, cursor still advances */
	xdr_init_dec(&x, b, 28);
	xdr_skip(&x, 12);
	CHECK_INT(xdr_get_string(&x, s, 4), LN_ENAMETOOLONG);
	CHECK_INT(x.pos, 24);
	/* opaque longer than the data / than max */
	{
		static const u8 bad[] = { 0, 0, 0, 9, 'a', 'b', 'c', 'd' };
		xdr_init_dec(&x, bad, sizeof(bad));
		CHECK(xdr_get_opaque(&x, &n, 100) == NULL);
		CHECK(x.err);
	}
	{
		static const u8 big[] = { 0, 0, 0, 65 };
		xdr_init_dec(&x, big, sizeof(big));
		CHECK_INT(xdr_get_fh(&x, &fh), LN_EPROTO);
	}
	/* encoder overflow is sticky */
	xdr_init_enc(&x, b, 6);
	xdr_put_u32(&x, 1);
	xdr_put_u32(&x, 2);
	CHECK(x.err);
	xdr_put_u32(&x, 3);
	CHECK_INT(x.pos, 4);
}

static void auth_and_call(void)
{
	u8 cred[RPC_CREDMAX], b[256];
	u32 gids[2] = { 10, 20 };
	NfsXdr x;
	size_t len;
	int n = rpc_auth_sys(cred, sizeof(cred), 0x5f000000, "amiga", 1000, 100, gids, 2);
	CHECK_INT(n, 4 + 4 + 8 + 4 + 4 + 4 + 8);
	CHECK_HEX(cred, (size_t)n, "5f00000000000005616d696761000000000003e800000064000000020000000a00000014");
	CHECK_HEX(cred + 16, 4, "000003e8");
	CHECK_HEX(cred + 24, 12, "000000020000000a00000014");

	/* NULL call to NFS v3, AUTH_NONE */
	xdr_init_enc(&x, b, sizeof(b));
	rpc_begin_call(&x, 0xdeadbeef, NFS_PROG, NFS_VERS, NFS3_NULL, NULL, 0);
	len = rpc_finish_call(&x);
	CHECK_INT(len, 44);
	CHECK_HEX(b, len, "80000028deadbeef0000000000000002000186a3000000030000000000000000000000000000000000000000");
	/* with AUTH_SYS */
	xdr_init_enc(&x, b, sizeof(b));
	rpc_begin_call(&x, 1, MOUNT_PROG, MOUNT_VERS, MNT3_MNT, cred, (size_t)n);
	xdr_put_string(&x, "/srv");
	len = rpc_finish_call(&x);
	CHECK_INT(ln_be32(b), 0x80000000u | (u32)(len - 4));
	CHECK_INT(ln_be32(b + 28), 1);          /* AUTH_SYS */
	CHECK_INT(ln_be32(b + 32), (u32)n);
	CHECK_HEX(b + len - 8, 8, "000000042f737276");
}

/* canned byte stream for rpc_read_record */
typedef struct Stream { const u8 *p; size_t n, pos; } Stream;
static int srd(void *ctx, void *buf, size_t n)
{
	Stream *s = ctx;
	if (n > s->n - s->pos) return LN_ECONNRESET;
	memcpy(buf, s->p + s->pos, n);
	s->pos += n;
	return LN_OK;
}

static void record_marking(void)
{
	static const u8 two[] = { 0x00, 0, 0, 3, 'a', 'b', 'c', 0x80, 0, 0, 2, 'd', 'e',
	                          0x80, 0, 0, 0 /* empty last fragment */ };
	static const u8 huge[] = { 0x80, 0, 0x10, 0 };
	static const u8 cut[] = { 0x80, 0, 0, 8, 'x' };
	Stream s;
	u8 *buf = NULL;
	size_t cap = 0, len = 0;
	s.p = two; s.n = sizeof(two); s.pos = 0;
	CHECK_INT(rpc_read_record(srd, &s, &buf, &cap, &len, 1024), LN_OK);
	CHECK_INT(len, 5);
	CHECK(!memcmp(buf, "abcde", 5));
	CHECK_INT(rpc_read_record(srd, &s, &buf, &cap, &len, 1024), LN_OK);
	CHECK_INT(len, 0);
	CHECK_INT(rpc_read_record(srd, &s, &buf, &cap, &len, 1024), LN_ECONNRESET);
	s.p = huge; s.n = sizeof(huge); s.pos = 0;
	CHECK_INT(rpc_read_record(srd, &s, &buf, &cap, &len, 1024), LN_EPROTO);
	s.p = cut; s.n = sizeof(cut); s.pos = 0;
	CHECK_INT(rpc_read_record(srd, &s, &buf, &cap, &len, 1024), LN_ECONNRESET);
	/* growth past the initial buffer */
	{
		u8 *big = ln_alloc(4 + 5000);
		ln_put_be32(big, 0x80000000u | 5000);
		memset(big + 4, 0x5a, 5000);
		s.p = big; s.n = 5004; s.pos = 0;
		CHECK_INT(rpc_read_record(srd, &s, &buf, &cap, &len, 8192), LN_OK);
		CHECK_INT(len, 5000);
		CHECK(cap >= 5000 && buf[4999] == 0x5a);
		ln_free(big);
	}
	ln_free(buf);
}

static void replies(void)
{
	size_t body = 0;
	static const u8 ok[] = { 0, 0, 0, 7, 0, 0, 0, 1, 0, 0, 0, 0, /* accepted */
	                         0, 0, 0, 0, 0, 0, 0, 0,               /* verf AUTH_NONE */
	                         0, 0, 0, 0,                           /* SUCCESS */
	                         0, 0, 0x08, 0x01 };                   /* result: port 2049 */
	static const u8 verf[] = { 0, 0, 0, 7, 0, 0, 0, 1, 0, 0, 0, 0,
	                           0, 0, 0, 1, 0, 0, 0, 5, 1, 2, 3, 4, 5, 0, 0, 0, /* 5-byte verifier */
	                           0, 0, 0, 0 };
	static const u8 progun[] = { 0, 0, 0, 7, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
	static const u8 mism[] = { 0, 0, 0, 7, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
	                           0, 0, 0, 2, 0, 0, 0, 4 };
	static const u8 garbage[] = { 0, 0, 0, 7, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4 };
	static const u8 syserr[] = { 0, 0, 0, 7, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5 };
	static const u8 tooweak[] = { 0, 0, 0, 7, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 5 };
	static const u8 rpcmis[] = { 0, 0, 0, 7, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 2 };
	static const u8 call[] = { 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 2 };
	static const u8 shortr[] = { 0, 0, 0, 7, 0, 0, 0, 1, 0, 0 };
	NfsXdr x;
	CHECK_INT(rpc_check_reply(ok, sizeof(ok), 7, &body), LN_OK);
	CHECK_INT(body, 24);
	xdr_init_dec(&x, ok + body, sizeof(ok) - body);
	CHECK_INT(xdr_get_u32(&x), 2049);
	CHECK_INT(rpc_check_reply(ok, sizeof(ok), 8, &body), RPC_XID_OTHER);
	CHECK_INT(rpc_check_reply(verf, sizeof(verf), 7, &body), LN_OK);
	CHECK_INT(body, 32);
	CHECK_INT(rpc_check_reply(progun, sizeof(progun), 7, &body), LN_ENOTSUP);
	CHECK_INT(rpc_check_reply(mism, sizeof(mism), 7, &body), LN_ENOTSUP);
	CHECK_INT(rpc_check_reply(garbage, sizeof(garbage), 7, &body), LN_EPROTO);
	CHECK_INT(rpc_check_reply(syserr, sizeof(syserr), 7, &body), LN_EIO);
	CHECK_INT(rpc_check_reply(tooweak, sizeof(tooweak), 7, &body), LN_EAUTH);
	CHECK(strstr(rpc_last_error, "weak") != NULL);
	CHECK_INT(rpc_check_reply(rpcmis, sizeof(rpcmis), 7, &body), LN_EPROTO);
	CHECK_INT(rpc_check_reply(call, sizeof(call), 7, &body), LN_EPROTO);
	CHECK_INT(rpc_check_reply(shortr, sizeof(shortr), 7, &body), LN_EPROTO);
}

static void attrs(void)
{
	/* post_op_attr with a fattr3: regular file, mode 0640, uid 1000 gid 100,
	 * size 70000, fileid 42, mtime 1700000000 */
	static const u8 pa[] = {
		0, 0, 0, 1,
		0, 0, 0, 1,  0, 0, 0x01, 0xa0,  0, 0, 0, 1,  0, 0, 0x03, 0xe8,  0, 0, 0, 100,
		0, 0, 0, 0, 0, 1, 0x11, 0x70,   0, 0, 0, 0, 0, 1, 0x20, 0,
		0, 0, 0, 0, 0, 0, 0, 0,         0, 0, 0, 0, 0, 0, 0, 9,
		0, 0, 0, 0, 0, 0, 0, 42,
		0x65, 0x53, 0xf1, 0x00, 0, 0, 0, 0,
		0x65, 0x53, 0xf1, 0x00, 0, 0, 0, 5,
		0x65, 0x53, 0xf1, 0x01, 0, 0, 0, 0,
		0, 0, 0, 0                      /* next: post_op_attr absent */
	};
	NfsXdr x;
	NfsAttr a;
	LnStat st;
	u32 g[1] = { 100 };
	xdr_init_dec(&x, pa, sizeof(pa));
	CHECK_INT(xdr_get_post_attr(&x, &a), 1);
	CHECK_INT(a.type, NF3REG); CHECK_INT(a.mode, 0640); CHECK_INT(a.uid, 1000); CHECK_INT(a.gid, 100);
	CHECK(a.size == 70000); CHECK(a.fileid == 42); CHECK(a.fsid == 9);
	CHECK_INT(a.mtime, 1700000000); CHECK_INT(a.ctime, 1700000001);
	CHECK_INT(xdr_get_post_attr(&x, &a), 0);
	CHECK(!x.err); CHECK_INT(x.pos, sizeof(pa));
	xdr_init_dec(&x, pa, sizeof(pa));
	xdr_get_post_attr(&x, &a);
	nfs_attr_to_stat(&a, 1000, 1000, NULL, 0, &st);          /* owner: rw- */
	CHECK_INT(st.type, LN_T_FILE); CHECK(st.size == 70000); CHECK_INT(st.mode, 0640);
	CHECK_INT(st.prot, LN_P_READ | LN_P_WRITE | LN_P_DELETE);
	CHECK_INT(st.ctime, st.mtime); CHECK(st.fileid == 42);
	nfs_attr_to_stat(&a, 2000, 50, g, 1, &st);               /* group via gids: r-- */
	CHECK_INT(st.prot, LN_P_READ);
	nfs_attr_to_stat(&a, 2000, 50, NULL, 0, &st);            /* other: --- */
	CHECK_INT(st.prot, 0);
	nfs_attr_to_stat(&a, 0, 0, NULL, 0, &st);                /* root */
	CHECK_INT(st.prot, LN_P_READ | LN_P_WRITE | LN_P_DELETE);
	a.type = NF3LNK;
	nfs_attr_to_stat(&a, 0, 0, NULL, 0, &st);
	CHECK_INT(st.type, LN_T_LINK);
	CHECK(!(st.prot & LN_P_HIDDEN));
	/* wcc_data: pre_op_attr present, post_op_attr absent */
	{
		static const u8 wcc[] = { 0, 0, 0, 1, 0,0,0,0,0,0,0,1, 0,0,0,2,0,0,0,0, 0,0,0,3,0,0,0,0, 0,0,0,0, 0xaa,0xbb,0xcc,0xdd };
		xdr_init_dec(&x, wcc, sizeof(wcc));
		CHECK_INT(xdr_get_wcc(&x, &a), 0);
		CHECK_INT(xdr_get_u32(&x), 0xaabbccdd);
	}
}

static void maps(void)
{
	CHECK_INT(nfs_stat_to_ln(0), LN_OK);
	CHECK_INT(nfs_stat_to_ln(1), LN_EACCES);
	CHECK_INT(nfs_stat_to_ln(2), LN_ENOENT);
	CHECK_INT(nfs_stat_to_ln(13), LN_EACCES);
	CHECK_INT(nfs_stat_to_ln(17), LN_EEXIST);
	CHECK_INT(nfs_stat_to_ln(20), LN_ENOTDIR);
	CHECK_INT(nfs_stat_to_ln(21), LN_EISDIR);
	CHECK_INT(nfs_stat_to_ln(28), LN_ENOSPC);
	CHECK_INT(nfs_stat_to_ln(30), LN_EROFS);
	CHECK_INT(nfs_stat_to_ln(63), LN_ENAMETOOLONG);
	CHECK_INT(nfs_stat_to_ln(66), LN_ENOTEMPTY);
	CHECK_INT(nfs_stat_to_ln(69), LN_ENOSPC);
	CHECK_INT(nfs_stat_to_ln(70), LN_ESTALE);
	CHECK_INT(nfs_stat_to_ln(10001), LN_ESTALE);
	CHECK_INT(nfs_stat_to_ln(10004), LN_ENOTSUP);
	CHECK_INT(nfs_stat_to_ln(10008), LN_EINUSE);
	CHECK_INT(nfs_stat_to_ln(12345), LN_EIO);
	CHECK_INT(mnt_stat_to_ln(0), LN_OK);
	CHECK_INT(mnt_stat_to_ln(2), LN_ENOSHARE);
	CHECK_INT(mnt_stat_to_ln(13), LN_EACCES);
	CHECK_INT(nfs_access_to_prot(ACCESS3_READ | ACCESS3_EXECUTE, LN_T_FILE), LN_P_READ | LN_P_EXEC);
	CHECK_INT(nfs_access_to_prot(0x3f, LN_T_FILE), LN_P_READ | LN_P_WRITE | LN_P_EXEC | LN_P_DELETE);
	CHECK_INT(nfs_access_to_prot(ACCESS3_READ | ACCESS3_LOOKUP, LN_T_DIR), LN_P_READ | LN_P_EXEC);
	CHECK_INT(nfs_access_to_prot(ACCESS3_EXTEND, LN_T_DIR), LN_P_WRITE | LN_P_DELETE);
}

int main(void)
{
	xdr();
	auth_and_call();
	record_marking();
	replies();
	attrs();
	maps();
	T_DONE("t_nfs_unit");
}
