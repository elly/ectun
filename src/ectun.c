/* ectun.c */

#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <polarssl/aes.h>
#include <polarssl/bignum.h>
#include <polarssl/md.h>
#include <polarssl/rsa.h>
#include <polarssl/sha2.h>

#include "crypto.h"
#include "ectun.h"

enum {
	BUF_MAX = 32768,

	F_HAVE_NONCES = 0x00000001,
	F_SERVER = 0x00000002,

	M_CLIENT_HELLO = 0x45431000,
	M_SERVER_HELLO = 0x45432000,
	M_SESSION = 0x45433000,

	S_NONE = 0,
	S_WAIT_CLIENT_HELLO = 1,
	S_WAIT_SERVER_HELLO = 2,
	S_GOT_CLIENT_HELLO = 3,
	S_SESSION = 4,
};

struct ectun {
	struct symm_ctx send;
	struct symm_ctx recv;

	unsigned int flags;

	nonce my_e;
	nonce my_m;
	nonce their_e;
	nonce their_m;
	symm_key ke;
	symm_key km;

	struct asymm_ctx my_asymm;
	struct asymm_ctx their_asymm;

	int state;

	ectun_keypred *kc;
	void *kcarg;
};

struct m_client_hello {
	unsigned int magic;

	/* Encrypted under Ksu */
	asymm_msg kt;

	/* Fields below here are encrypted under Kt */
	struct {
		nonce nce;
		nonce ncm;
		asymm_pubkey kcu;
	} body;
};

struct m_server_hello {
	unsigned int magic;
	union {
		struct {
			nonce nse;
			nonce nsm;
			hash_val hnce;
			hmac_val hmacv;
		} body;
		asymm_msg e_body;
	};
};

int ectun_genkey(ectun_ukey *ukey, ectun_pkey *pkey) {
	struct asymm_ctx ctx;
	asymm_init(&ctx);
	asymm_gen(&ctx);
	*ukey = asymm_ukey(&ctx);
	*pkey = asymm_pkey(&ctx);
	return 0;
}

static void s_clihello(struct ectun *ec, unsigned char *buf, size_t sz) {
	struct m_client_hello msg;
	symm_key kt;
	struct symm_ctx ctx;

	assert(sz >= sizeof(msg));
	msg.magic = M_CLIENT_HELLO;

	/* Generate Kt, compute Ea(Ksu, Kt) */
	symm_gen(kt);
	symm_init(&ctx, kt, 0);
	asymm_encrypt(&ec->their_asymm, sizeof(kt), kt, msg.kt);

	memcpy(msg.body.nce, ec->my_e, sizeof(ec->my_e));
	memcpy(msg.body.ncm, ec->my_m, sizeof(ec->my_m));
	asymm_write_ukey(&ec->my_asymm, msg.body.kcu);
	symm(&ctx, sizeof(msg.body), (byte *)&msg.body, (byte *)&msg.body);

	memcpy(buf, &msg, sizeof(msg));
	ec->state = S_WAIT_SERVER_HELLO;
}

static void s_srvhello(struct ectun *ec, unsigned char *buf, size_t sz) {
	struct m_server_hello msg;
	char b[2048];
	int r;

	msg.magic = M_SERVER_HELLO;
	assert(sz >= sizeof(msg));

	memcpy(msg.body.nse, ec->my_e, sizeof(ec->my_e));
	memcpy(msg.body.nsm, ec->my_m, sizeof(ec->my_m));
	hash(sizeof(ec->their_e), ec->their_e, msg.body.hnce);
	hmac(ec->km, sizeof(msg.body) - sizeof(msg.body.hmacv), (byte *)&msg.body, msg.body.hmacv);
	r = asymm_encrypt(&ec->their_asymm, sizeof(msg.body), msg.e_body, msg.e_body);
	if (r) {
		error_strerror(r, b, sizeof(b));
		printf("%d: %s\n", r, b);
	}

	memcpy(buf, &msg, sizeof(msg));
	ec->state = S_SESSION;
} 

static struct ectun *ectun_new(void) {
	struct ectun *e = malloc(sizeof *e);
	if (!e)
		return NULL;
	e->flags = 0;
	mknonce(e->my_e);
	mknonce(e->my_m);
	asymm_init(&e->my_asymm);
	asymm_init(&e->their_asymm);
	return e;
}

struct ectun *ectun_new_client(char *sukey, char *cpkey) {
	struct ectun *e = ectun_new();
	if (!e)
		return NULL;
	asymm_set_ukey(&e->their_asymm, sukey);
	asymm_set_pkey(&e->my_asymm, cpkey);
	e->state = S_NONE;
	return e;
}

struct ectun *ectun_new_server(char *spkey, ectun_keypred *kc, void *arg) {
	struct ectun *e = ectun_new();
	if (!e)
		return NULL;
	asymm_set_pkey(&e->my_asymm, spkey);
	e->kc = kc;
	e->kcarg = arg;
	e->flags |= F_SERVER;
	e->state = S_WAIT_CLIENT_HELLO;
	return e;
}

static int r_clihello(struct ectun *ec, const unsigned char *buf, size_t sz) {
	struct m_client_hello msg;
	symm_key kt;
	struct symm_ctx ctx;

	if (sz != sizeof(msg))
		return ECTUN_ERR_BADMSG;
	memcpy(&msg, buf, sz);
	if (asymm_decrypt(&ec->my_asymm, sizeof(msg.kt), msg.kt, kt) != sizeof(kt))
		return ECTUN_ERR_BADMSG;
	symm_init(&ctx, kt, 0);
	symm(&ctx, sizeof(msg.body), (byte *)&msg.body, (byte *)&msg.body);

	memcpy(ec->their_e, &msg.body.nce, sizeof(msg.body.nce));
	memcpy(ec->their_m, &msg.body.ncm, sizeof(msg.body.ncm));
	xorbytes(sizeof(ec->ke), ec->their_e, ec->my_e, ec->ke);
	xorbytes(sizeof(ec->km), ec->their_m, ec->my_m, ec->km);

	if (asymm_read_ukey(&ec->their_asymm, msg.body.kcu))
		return ECTUN_ERR_BADMSG;

	symm_init(&ec->send, ec->ke, 1);
	symm_init(&ec->recv, ec->ke, 0);
	ec->state = S_GOT_CLIENT_HELLO;

	printf("clihello ok\n");
	return 0;
}

static int r_srvhello(struct ectun *ec, const unsigned char *buf, size_t sz) {
	struct m_server_hello msg;
	hash_val hv;
	int r;
	char b[2048];

	if (sz != sizeof(msg))
		return ECTUN_ERR_BADMSG;

	memcpy(&msg, buf, sz);
	r = asymm_decrypt(&ec->my_asymm, sizeof(msg.e_body), msg.e_body, msg.e_body);
	if (r < 0) {
		error_strerror(r, b, sizeof(b));
		printf("%d: %s\n", r, b);
		return r;
	}

	if (r != sizeof(msg.body))
		return ECTUN_ERR_BADMSG;

	memcpy(ec->their_e, msg.body.nse, sizeof(ec->their_e));
	memcpy(ec->their_m, msg.body.nsm, sizeof(ec->their_m));
	xorbytes(sizeof(ec->ke), ec->their_e, ec->my_e, ec->ke);
	xorbytes(sizeof(ec->km), ec->their_m, ec->my_m, ec->km);

	if (!hmac_ok(ec->km, sizeof(msg.body), (byte *)&msg.body))
		return ECTUN_ERR_HMACFAIL;
	hash(sizeof(ec->my_e), ec->my_e, hv);
	if (memcmp(hv, msg.body.hnce, sizeof(hv)))
		return ECTUN_ERR_BADMSG;
	symm_init(&ec->send, ec->ke, 0);
	symm_init(&ec->recv, ec->ke, 1);
	ec->state = S_SESSION;
	printf("srvhello ok\n");
	return 0;
}

int ectun_needsinput(struct ectun *ec) {
	if (ec->flags & F_SERVER)
		return ec->state == S_WAIT_CLIENT_HELLO;
	else
		return ec->state == S_WAIT_SERVER_HELLO;
}

int ectun_input(struct ectun *ec, const unsigned char *buf, size_t sz) {
	/* This doesn't work on machines where sizeof(int) != 4 */
	unsigned int type;
	type = *(unsigned int *)buf;
	if (ec->flags & F_SERVER && type == M_CLIENT_HELLO)
		return r_clihello(ec, buf, sz);
	else if (!(ec->flags & F_SERVER) && type == M_SERVER_HELLO)
		return r_srvhello(ec, buf, sz);
	return ECTUN_ERR_BADMSG;
}

size_t ectun_hasoutput(struct ectun *ec) {
	if (ec->flags & F_SERVER)
		/* Need to reply to client hello */
		return ec->state == S_GOT_CLIENT_HELLO ? sizeof(struct m_server_hello) : 0;
	else
		/* Need to send client hello */
		return ec->state == S_NONE ? sizeof(struct m_client_hello) : 0;
}

void ectun_output(struct ectun *ec, unsigned char *buf, size_t sz) {
	if (ec->flags & F_SERVER && ec->state == S_GOT_CLIENT_HELLO)
		s_srvhello(ec, buf, sz);
	else if (!(ec->flags & F_SERVER) && ec->state == S_NONE)
		s_clihello(ec, buf, sz);
}

ssize_t ectun_recv(struct ectun *ec, const unsigned char *inbuf, size_t sz, unsigned char *outbuf) {
	/* Messages on the wire are HMAC(Km, Es(Ke, b)) */
	if (sz < sizeof(hmac_val))
		return ECTUN_ERR_BADMSG;
	if (!hmac_ok(ec->km, sz, inbuf))
		return ECTUN_ERR_HMACFAIL;
	sz -= sizeof(hmac_val);
	symm(&ec->recv, sz, inbuf, outbuf);
	return sz;
}

size_t ectun_sendsize(struct ectun *ec, size_t sz) {
	return sz + sizeof(hmac_val);
}

void ectun_send(struct ectun *ec, const unsigned char *inbuf, size_t sz, unsigned char *outbuf) {
	symm(&ec->send, sz, inbuf, outbuf);
	hmac(ec->km, sz, outbuf, outbuf + sz);
}
