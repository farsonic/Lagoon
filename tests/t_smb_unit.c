/* Lagoon - SMB unit tests: NTLMv2 (MS-NLMP 4.2.4 vectors), NTLMSSP MAC,
 * SMB 3.x KDF and signing (HMAC-SHA256, AES-CMAC, AES-GMAC; expected
 * values computed independently with Python's hmac/cryptography), NTSTATUS
 * mapping, times, UTF-16 paths.
 * SPDX-License-Identifier: GPL-2.0-only */
#include "testutil.h"
#include "smb/smb_int.h"
#include "ln_charset.h"

static void ntlm(void)
{
	u8 key[16], proof[16], base[16], temp[128], esk[16], enc[16], d[64], sk[16], sealk[16], msg[32], sig[16];
	u8 srvchal[8] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
	int k = 0, l;
	LnRc4 rc;
	LnMd5 m;
	/* MS-NLMP 4.2.4.1.1 NTOWFv2 */
	ntlm_ntowfv2("User", "Domain", "Password", key);
	CHECK_HEX(key, 16, "0c868a403bfd7a93a3001ef22ef02e3f");
	/* lower-case user name gives the same key (upper-cased) */
	ntlm_ntowfv2("user", "Domain", "Password", d);
	CHECK(!memcmp(d, key, 16));
	/* 4.2.4.2.2: temp = 0101 Z(6) time(0) cc Z(4) avpairs Z(4) */
	memset(temp, 0, sizeof(temp));
	temp[0] = 1; temp[1] = 1;
	memset(temp + 16, 0xaa, 8);
	k = 28;
	ln_put_le16(temp + k, 2); l = ln_utf8_to_utf16le("Domain", 6, temp + k + 4, 64); ln_put_le16(temp + k + 2, (u16)l); k += 4 + l;
	ln_put_le16(temp + k, 1); l = ln_utf8_to_utf16le("Server", 6, temp + k + 4, 64); ln_put_le16(temp + k + 2, (u16)l); k += 4 + l;
	k += 4 + 4;                              /* MsvAvEOL + Z(4) */
	ntlm_v2_proof(key, srvchal, temp, (size_t)k, proof, base);
	CHECK_HEX(proof, 16, "68cd0ab851e51c96aabc927bebef6a1c");
	CHECK_HEX(base, 16, "8de40ccadbc14a82f15cb0ad0de95ca3");
	/* 4.2.4.2.3 encrypted session key = RC4(base, 55..55) */
	memset(esk, 0x55, 16);
	ln_rc4_init(&rc, base, 16);
	ln_rc4_crypt(&rc, esk, enc, 16);
	CHECK_HEX(enc, 16, "c5dad2544fc9799094ce1ce90bc9d03e");
	/* 4.2.4.1.2: LMv2 = HMAC_MD5(key, srvchal | cc) */
	{
		LnHmacMd5 h;
		u8 cc[8];
		memset(cc, 0xaa, 8);
		ln_hmac_md5_init(&h, key, 16);
		ln_hmac_md5_update(&h, srvchal, 8);
		ln_hmac_md5_update(&h, cc, 8);
		ln_hmac_md5_final(&h, d);
		CHECK_HEX(d, 16, "86c35097ac9cec102554764a57cccc19");
	}
	/* 4.2.4.4: client signing/sealing keys and the signature after sealing "Plaintext" */
	ln_md5_init(&m); ln_md5_update(&m, esk, 16);
	ln_md5_update(&m, "session key to client-to-server signing key magic constant", 59);
	ln_md5_final(&m, sk);
	CHECK_HEX(sk, 16, "4788dc861b4782f35d43fd98fe1a2d39");
	ln_md5_init(&m); ln_md5_update(&m, esk, 16);
	ln_md5_update(&m, "session key to client-to-server sealing key magic constant", 59);
	ln_md5_final(&m, sealk);
	CHECK_HEX(sealk, 16, "59f600973cc4960a25480a7c196e4c58");
	l = ln_utf8_to_utf16le("Plaintext", 9, msg, sizeof(msg));
	ln_rc4_init(&rc, sealk, 16);
	ln_rc4_crypt(&rc, msg, d, (size_t)l);
	CHECK_HEX(d, l, "54e50165bf1936dc996020c1811b0f06fb5f");
	ntlm_mac(sk, &rc, 0, msg, (size_t)l, sig);
	CHECK_HEX(sig, 16, "010000007fb38ec5c55d497600000000");
}

static void kdf_sign(void)
{
	u8 sk[16], pa[64], out[32], m[68], sig[16];
	SmbConn c;
	int i;
	for (i = 0; i < 16; i++) sk[i] = (u8)(0x10 + i);
	for (i = 0; i < 64; i++) pa[i] = (u8)i;
	smb_kdf(sk, 16, "SMB2AESCMAC", 12, "SmbSign", 8, out, 128);
	CHECK_HEX(out, 16, "24f1f0fdb269db9836d70efbbb97413f");
	smb_kdf(sk, 16, "SMB2AESCCM", 11, "ServerIn ", 10, out, 128);
	CHECK_HEX(out, 16, "fe85e20ea4633a2437828b14d1833584");
	smb_kdf(sk, 16, "SMBSigningKey", 14, pa, 64, out, 128);
	CHECK_HEX(out, 16, "a3121cdda796d2a68c2fb753a0d2dc95");
	smb_kdf(sk, 16, "SMBC2SCipherKey", 16, pa, 64, out, 256);
	CHECK_HEX(out, 32, "b7758e1f94872a7f25f245f4b6b099678c120b983e014249c173c5e13584a9d2");

	/* sign a header-only message (mid 5, flags SIGNED) + 4-byte body */
	memset(m, 0, sizeof(m));
	m[0] = 0xfe; m[1] = 'S'; m[2] = 'M'; m[3] = 'B'; m[4] = 64; m[16] = 8; m[24] = 5; m[64] = 4;
	memset(&c, 0, sizeof(c));
	memcpy(c.sign_key, sk, 16);
	c.sign_algo = SMB_SIGN_HMAC;
	smb_sign_msg(&c, m, 68, sig);
	CHECK_HEX(sig, 16, "a1fe79bfb19896f206ba121bbd3e58ee");
	c.sign_algo = SMB_SIGN_CMAC;
	ln_aes_setkey(&c.sign_aes, sk, 16);
	smb_sign_msg(&c, m, 68, sig);
	CHECK_HEX(sig, 16, "536d8837a3295335874a024e17148624");
	c.sign_algo = SMB_SIGN_GMAC;
	c.sign_gcm = ln_alloc(sizeof(LnGcm));
	ln_gcm_setkey(c.sign_gcm, sk, 16);
	smb_sign_msg(&c, m, 68, sig);
	CHECK_HEX(sig, 16, "7f30945e95b3d3f5b7b9f24989ca0cb5");
	/* smb_verify: a correct and a tampered signature */
	memcpy(m + 48, sig, 16);
	c.msg = m; c.msglen = 68;
	CHECK_INT(smb_verify(&c), 0);
	m[66] ^= 1;
	CHECK_INT(smb_verify(&c), LN_ECRYPTO);
	ln_free(c.sign_gcm);
}

static void status(void)
{
	CHECK_INT(smb_err(0), LN_OK);
	CHECK_INT(smb_err(0xC0000034u), LN_ENOENT);
	CHECK_INT(smb_err(0xC000003Au), LN_ENOENT);
	CHECK_INT(smb_err(0xC0000022u), LN_EACCES);
	CHECK_INT(smb_err(0xC0000043u), LN_EINUSE);
	CHECK_INT(smb_err(0xC0000101u), LN_ENOTEMPTY);
	CHECK_INT(smb_err(0xC0000035u), LN_EEXIST);
	CHECK_INT(smb_err(0xC000007Fu), LN_ENOSPC);
	CHECK_INT(smb_err(0xC000006Du), LN_EAUTH);
	CHECK_INT(smb_err(0xC00000CCu), LN_ENOSHARE);
	CHECK_INT(smb_err(0xC000035Cu), LN_ECONNRESET);
	CHECK_INT(smb_err(0xC00000BAu), LN_EISDIR);
	CHECK_INT(smb_err(0xC0000103u), LN_ENOTDIR);
	CHECK_INT(smb_err(0xC0000121u), LN_EACCES);
	CHECK_INT(smb_err(0xC000A000u), LN_ECRYPTO);
	CHECK_INT(smb_err(0xC0001234u), LN_EIO);     /* unknown error */
	CHECK_INT(smb_err(0x00000001u), LN_OK);      /* unknown success/info */
	CHECK_STR(smb_status_name(0xC0000043u), "SHARING_VIOLATION");
	CHECK_STR(smb_status_name(0x80000006u), "NO_MORE_FILES");
	CHECK_STR(smb_status_name(0xC0001234u), "NTSTATUS 0xc0001234");
}

static void misc(void)
{
	u8 b[256];
	int n;
	CHECK_INT(smb_ft2unix(116444736000000000ULL), 0);
	CHECK_INT(smb_ft2unix(132539616000000000ULL), 1609488000u);     /* 2021-01-01 08:00 UTC */
	CHECK(smb_unix2ft(1609488000u) == 132539616000000000ULL);
	CHECK_INT(smb_ft2unix(0), 0);
	n = smb_path16("", "a/b.txt", b, sizeof(b));
	CHECK_INT(n, 14);
	CHECK_HEX(b, 14, "61005c0062002e00740078007400");
	n = smb_path16("sub/dir", "", b, sizeof(b));
	CHECK_INT(n, 14);
	CHECK_HEX(b, 14, "7300750062005c00640069007200");
	n = smb_path16("", "", b, sizeof(b));
	CHECK_INT(n, 0);
	n = smb_path16("", "\xc3\xa9t\xc3\xa9/x", b, sizeof(b));          /* "été/x" */
	CHECK_INT(n, 10);
	CHECK_HEX(b, 10, "e9007400e9005c007800");
	CHECK_INT(smb_path16("", "abcdefgh", b, 8), LN_ENAMETOOLONG);
}

int main(void)
{
	ntlm();
	kdf_sign();
	status();
	misc();
	T_DONE("t_smb_unit");
}
