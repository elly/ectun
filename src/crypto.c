#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <polarssl/dhm.h>
#include <polarssl/error.h>
#include <polarssl/md.h>
#include <polarssl/sha2.h>

#include "crypto.h"

enum {
	E = 65537,
};

int memeq(size_t len, const byte *a, const byte *b) {
	int eq = 0;
	size_t i;
	for (i = 0; i < len; i++)
		eq |= (a[i] ^ b[i]);
	return !!eq;
}

void hexify(size_t len, const byte *in, char *out) {
	size_t i;
	for (i = 0; i < len; i++)
		sprintf(out + 2 * i, "%02x", in[i]);
}

void randbytes(size_t len, byte *buf) {
	static int devrandom = -1;
	if (devrandom == -1)
		devrandom = open("/dev/urandom", O_RDONLY);
	if (devrandom == -1)
		abort();
	read(devrandom, buf, len);
}

void xorbytes(size_t len, const byte *a, const byte *b, byte *c) {
	size_t i;
	for (i = 0; i < len; i++)
		c[i] = a[i] ^ b[i];
}

void mknonce(nonce n) {
	assert(sizeof(nonce) == 32);
	randbytes(sizeof(nonce), n);
}

static int _rng(void __attribute__((unused)) *arg) {
	int buf;
	randbytes(sizeof(buf), (byte *)&buf);
	return buf;
}

void symm_init(struct symm_ctx *ctx, const symm_key key, int high) {
	aes_setkey_enc(&ctx->ctx, key, sizeof(symm_key) * 8);
	memset(&ctx->block, 0, sizeof(ctx->block));
	memset(&ctx->ctr, 0, sizeof(ctx->ctr));
	if (high)
		ctx->ctr[0] = 0x80;
	ctx->offset = 0;
}

void symm_gen(symm_key key) {
	randbytes(sizeof(symm_key), key);
}

void symm(struct symm_ctx *ctx, size_t sz, const byte *in, byte *out) {
	int i;

	while (sz--) {
		if (!ctx->offset) {
			/* Ran out of keystream. */
			aes_crypt_ecb(&ctx->ctx, AES_ENCRYPT, ctx->ctr, ctx->block);
			i = 15;
			do {
				ctx->ctr[i]++;
			} while (ctx->ctr[i] == 0 && i--);
		}
		*out++ = *in++ ^ ctx->block[ctx->offset];
		ctx->offset = (ctx->offset + 1) & 0xF;
	}
}

void hash(size_t sz, const byte *in, byte *out) {
	sha2(in, sz, out, 0);
}

void hmac(hmac_key k, size_t sz, const byte *in, byte *out) {
	sha2_hmac(k, sizeof(hmac_key), in, sz, out, 0);
}

int hmac_ok(hmac_key k, size_t sz, const byte *in) {
	hmac_val hv;
	if (sz < sizeof(hv))
		/* too short */
		return 0;
	hmac(k, sz - sizeof(hv), in, hv);
	return memeq(sizeof(hv), in + sz - sizeof(hv), hv);
}

void asymm_init(struct asymm_ctx *ctx) {
	rsa_init(&ctx->rsa, RSA_PKCS_V21, POLARSSL_MD_SHA256);
	mpi_lset(&ctx->rsa.E, E);
}

int asymm_gen(struct asymm_ctx *ctx) {
	int r = rsa_gen_key(&ctx->rsa, _rng, NULL, sizeof(asymm_pubkey) * 8, E);
	char b[2048];
	error_strerror(r, b, sizeof(b));
	return 0;
}

char *asymm_ukey(struct asymm_ctx *ctx) {
	/* "ectun-ukey:" n */
	static const char *tag = "ectun-ukey";
	size_t nlen = 0;
	char *buf;

	mpi_write_string(&ctx->rsa.N, 16, NULL, &nlen);
	buf = malloc(strlen(tag) + 1 + nlen);
	if (!buf)
		return NULL;
	sprintf(buf, "%s:", tag);
	mpi_write_string(&ctx->rsa.N, 16, buf + strlen(tag) + 1, &nlen);
	return buf;
}

char *asymm_pkey(struct asymm_ctx *ctx) {
	/* "ectun-pkey:" n ":" d ":" p ":" q */
	static const char *tag = "ectun-pkey";
	size_t nlen = 0, dlen = 0, plen = 0, qlen = 0;
	size_t dplen = 0, dqlen = 0, qplen = 0;
	char *nbuf = NULL, *dbuf = NULL, *pbuf = NULL, *qbuf = NULL;
	char *dpbuf = NULL, *dqbuf = NULL, *qpbuf = NULL;
	char *buf = NULL;

	mpi_write_string(&ctx->rsa.N, 16, NULL, &nlen);
	mpi_write_string(&ctx->rsa.D, 16, NULL, &dlen);
	mpi_write_string(&ctx->rsa.P, 16, NULL, &plen);
	mpi_write_string(&ctx->rsa.Q, 16, NULL, &qlen);
	mpi_write_string(&ctx->rsa.DP, 16, NULL, &dplen);
	mpi_write_string(&ctx->rsa.DQ, 16, NULL, &dqlen);
	mpi_write_string(&ctx->rsa.QP, 16, NULL, &qplen);
	nbuf = malloc(nlen);
	dbuf = malloc(dlen);
	pbuf = malloc(plen);
	qbuf = malloc(qlen);
	dpbuf = malloc(dplen);
	dqbuf = malloc(dqlen);
	qpbuf = malloc(qplen);
	if (!nbuf || !dbuf || !pbuf || !qbuf || !dpbuf || !dqbuf || !qpbuf)
		goto out;
	mpi_write_string(&ctx->rsa.N, 16, nbuf, &nlen);
	mpi_write_string(&ctx->rsa.D, 16, dbuf, &dlen);
	mpi_write_string(&ctx->rsa.P, 16, pbuf, &plen);
	mpi_write_string(&ctx->rsa.Q, 16, qbuf, &qlen);
	mpi_write_string(&ctx->rsa.DP, 16, dpbuf, &dplen);
	mpi_write_string(&ctx->rsa.DQ, 16, dqbuf, &dqlen);
	mpi_write_string(&ctx->rsa.QP, 16, qpbuf, &qplen);

	/* The null terminators on d and p are replaced with : */
	buf = malloc(strlen(tag) + 5 + strlen(nbuf) + strlen(dbuf)
	             + strlen(pbuf) + strlen(qbuf) + strlen(dpbuf)
	             + strlen(dqbuf) + strlen(qpbuf));
	sprintf(buf, "%s:%s:%s:%s:%s:%s:%s:%s", tag, nbuf, dbuf, pbuf, qbuf,
	        dpbuf, dqbuf, qpbuf);
out:
	free(nbuf);
	free(dbuf);
	free(pbuf);
	free(qbuf);
	free(dpbuf);
	free(dqbuf);
	free(qpbuf);
	return buf;
}

int asymm_set_ukey(struct asymm_ctx *ctx, char *ukey) {
	static const char *tag = "ectun-ukey:";
	if (strstr(ukey, tag) != ukey)
		return 1;
	ukey += strlen(tag);
	mpi_read_string(&ctx->rsa.N, 16, ukey);
	mpi_lset(&ctx->rsa.E, E);
	ctx->rsa.len = mpi_size(&ctx->rsa.N);
	return 0;
}

int asymm_set_pkey(struct asymm_ctx *ctx, char *pkey) {
	static const char *tag = "ectun-pkey:";
	char *v;
	if (strstr(pkey, tag) != pkey)
		return 1;
	pkey += strlen(tag);
	v = strsep(&pkey, ":");
	mpi_read_string(&ctx->rsa.N, 16, v);
	v = strsep(&pkey, ":");
	mpi_read_string(&ctx->rsa.D, 16, v);
	v = strsep(&pkey, ":");
	mpi_read_string(&ctx->rsa.P, 16, v);
	v = strsep(&pkey, ":");
	mpi_read_string(&ctx->rsa.Q, 16, v);
	v = strsep(&pkey, ":");
	mpi_read_string(&ctx->rsa.DP, 16, v);
	v = strsep(&pkey, ":");
	mpi_read_string(&ctx->rsa.DQ, 16, v);
	v = strsep(&pkey, ":");
	mpi_read_string(&ctx->rsa.QP, 16, v);
	ctx->rsa.len = mpi_size(&ctx->rsa.N);
	if (rsa_check_privkey(&ctx->rsa))
		assert(0);
	return 0;
}

void asymm_write_ukey(struct asymm_ctx *ctx, asymm_pubkey ukey) {
	mpi_write_binary(&ctx->rsa.N, ukey, mpi_size(&ctx->rsa.N));
}

int asymm_read_ukey(struct asymm_ctx *ctx, const asymm_pubkey ukey) {
	int r = mpi_read_binary(&ctx->rsa.N, ukey, sizeof(asymm_pubkey));
	ctx->rsa.len = mpi_size(&ctx->rsa.N);
	return r;
}

int asymm_encrypt(struct asymm_ctx *ctx, size_t len, const asymm_msg in, asymm_msg out) {
	asymm_msg m;
	int r = rsa_pkcs1_encrypt(&ctx->rsa, _rng, NULL, RSA_PUBLIC, len, in, m);
	memcpy(out, m, sizeof(m));
	return r;
}

ssize_t asymm_decrypt(struct asymm_ctx *ctx, size_t len, const asymm_msg in, asymm_msg out) {
	asymm_msg m;
	size_t plainlen;
	int r = rsa_pkcs1_decrypt(&ctx->rsa, RSA_PRIVATE, &plainlen, in, m, len);
	if (r)
		return r;
	memcpy(out, m, plainlen);
	return plainlen;
}

int asymm_sign(struct asymm_ctx *ctx, const hash_val hash, asymm_msg sig) {
	return rsa_pkcs1_sign(&ctx->rsa, _rng, NULL, RSA_PRIVATE,
	                      SIG_RSA_SHA256, 0, hash, sig);
}

int asymm_verify(struct asymm_ctx *ctx, const hash_val hash, asymm_msg sig) {
	return rsa_pkcs1_verify(&ctx->rsa, RSA_PUBLIC, SIG_RSA_SHA256,
	                        0, hash, sig);
}

static const char *dh_modulus =
"00feead19dbeaf90f61cfca1065d69db08839a2a2b6aef2488abd7531fbb"
"3e462e7dcecefbcedcbbbdf56549ee951530568188c3d97294166b6aaba0"
"aa5cc8555f9125503a180e90324c7f39c6a3452f3142ee72ab7dffc74c52"
"8db6da76d9c644f55d083e9cde74f7e742413b69476617d2670f2bf6d59f"
"fcd7c3bddeed41e2bd2ccdd9e612f1056cab88c441d7f9ba74651ed1a84d"
"407a27d71895f777ab6c7763cc00e6f1c30b2fe79446927e74bc73b8431b"
"53011af5ad1515e63dc1de83cc802ece7dfc71fbdf179f8e41d7f1b43eba"
"75d5a9c3b11d4f1b0b5a0988a9aacbccc1051226dc8410e41693ec8591e3"
"1ee2f5afdfaede122d1277fc270be4d25c1137a58be961eac9f27d4c71e2"
"391904dd6ab27bece5bd6c64c79b146c2d208cd63a4b74f8dae638dbe2c8"
"806ba107738a8df5cfe214a4b73d03c91275fba5728146ce5fec01775b74"
"481adf86f4854d65f5da4bb67f882a60ce0bca0acd157aa377f10b091ad0"
"b568893039eca33cdcb61ba8c9e32a87a2f5d8b7fd26734d2f096792352d"
"70ade9f4a51d8488bc57d32a638e0b14d6693f6776fffb355fedf652201f"
"a70cb8db34fb549490951a701e04ad49d671b74d089caa8c0e5e833a2129"
"1d6978f918f25d5c769bdbe4bb72a84a1afe6a0bbad18d3eacc7b454af40"
"8d4f1ccb23b9ae576fdae2d1a68f43d275741db19eedc3b81b5e56964f5f"
"8c3363";
static const size_t dh_modulus_sz = 512;

int dh_init(struct dh_ctx *ctx) {
	byte buf[dh_modulus_sz];
	memset(&ctx->dhm, 0, sizeof(ctx->dhm));
	mpi_read_string(&ctx->dhm.P, 16, dh_modulus);
	mpi_lset(&ctx->dhm.G, 2);
	ctx->dhm.len = mpi_size(&ctx->dhm.P);
	return dhm_make_public(&ctx->dhm, (sizeof(symm_key) + sizeof(hmac_key)) * 8,
	                       buf, sizeof(buf), _rng, NULL);
}

char *dh_ukey(struct dh_ctx *ctx) {
	size_t sz = 0;
	char *buf;
	mpi_write_string(&ctx->dhm.GX, 16, NULL, &sz);
	buf = malloc(sz);
	if (!buf)
		return NULL;
	mpi_write_string(&ctx->dhm.GX, 16, buf, &sz);
	return buf;
}

int dh_got(struct dh_ctx *ctx, const char *ukey) {
	return mpi_read_string(&ctx->dhm.GY, 16, ukey);
}

int dh_final(struct dh_ctx *ctx, symm_key ke, hmac_key km) {
	byte buf[dh_modulus_sz];
	size_t sz = sizeof(buf);
	int r = dhm_calc_secret(&ctx->dhm, buf, &sz);
	if (sz < sizeof(buf))
		return 1;
	memcpy(ke, buf, sizeof(symm_key));
	memcpy(km, buf + sizeof(symm_key), sizeof(hmac_key));
	return r;
}
