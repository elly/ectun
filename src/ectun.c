/* ectun.c */

#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <polarssl/aes.h>
#include <polarssl/bignum.h>
#include <polarssl/error.h>
#include <polarssl/md.h>
#include <polarssl/rsa.h>
#include <polarssl/sha2.h>

#include <ectun/crypto.h>
#include <ectun/ectun.h>

enum {
	BUF_MAX = 32768,

	F_HAVE_NONCES = 0x00000001,
	F_SERVER = 0x00000002,

	M_CLIENT_HELLO = 0x45431000,
	M_CLIENT_SIG = 0x45431001,
	M_SERVER_HELLO = 0x45432000,
	M_SESSION = 0x45433000,

	/* State encoding:
	 * bit 31 = client needs input
	 * bit 30 = server needs input
	 * bit 29 = client has output
	 * bit 28 = server has output
	 */
	SF_CLIENT_IN = 0x80000000,
	SF_SERVER_IN = 0x40000000,
	SF_CLIENT_OUT = 0x20000000,
	SF_SERVER_OUT = 0x10000000,

	S_NONE = 0x20000000,
	S_WAIT_CLIENT_HELLO = 0x40000000,
	S_WAIT_SERVER_HELLO = 0x80000000,
	S_WAIT_CLIENT_SIG = 0x40000001,
	S_GOT_CLIENT_HELLO = 0x10000000,
	S_GOT_SERVER_HELLO = 0x20000001,
	S_SESSION = 0x00000001,
};

struct ectun {
	struct symm_ctx send;
	struct symm_ctx recv;

	unsigned int flags;

	symm_key ke;
	hmac_key km;

	struct asymm_ctx my_asymm;
	struct asymm_ctx their_asymm;

	struct dh_ctx dh;

	int state;

	ectun_keypred kc;
	void *kcarg;
	hash_val hkcu;
};

struct m_client_hello {
	unsigned int magic;
	struct {
		asymm_pubkey kcu;
		dh_pubkey ga;
	} m;
	asymm_msg sig;
};

struct m_server_hello {
	unsigned int magic;
	struct {
		dh_pubkey ga;
		dh_pubkey gb;
	} m;
	asymm_msg sig;
};

struct m_client_sig {
	unsigned int magic;
	dh_pubkey gb;
	asymm_msg sig;
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
	hash_val hv;

	assert(sz >= sizeof(msg));
	memset(&msg, 0, sizeof(msg));
	msg.magic = M_CLIENT_HELLO;

	asymm_write_ukey(&ec->my_asymm, msg.m.kcu);
	dh_write_sukey(&ec->dh, msg.m.ga);
	hash(sizeof(msg.m), (void *)&msg.m, hv);
	asymm_sign(&ec->my_asymm, hv, msg.sig);

	memcpy(buf, &msg, sizeof(msg));

	ec->state = S_WAIT_SERVER_HELLO;
}

static void s_srvhello(struct ectun *ec, unsigned char *buf, size_t sz) {
	struct m_server_hello msg;
	hash_val hv;
	char hexhash[sizeof(hash_val) * 2 + 1];

	memset(&msg, 0, sizeof(msg));
	msg.magic = M_SERVER_HELLO;
	assert(sz >= sizeof(msg));

	dh_write_rukey(&ec->dh, msg.m.ga);
	dh_write_sukey(&ec->dh, msg.m.gb);
	hash(sizeof(msg.m), (void *)&msg.m, hv);
	asymm_sign(&ec->my_asymm, hv, msg.sig);

	memcpy(buf, &msg, sizeof(msg));
	hexify(sizeof(ec->hkcu), ec->hkcu, hexhash);

	if (ec->kc && !ec->kc(hexhash, ec->kcarg))
		ec->state = S_NONE;
	else
		ec->state = S_WAIT_CLIENT_SIG;
}

static void s_clisig(struct ectun *ec, unsigned char *buf, size_t sz) {
	struct m_client_sig msg;
	hash_val hv;

	assert(sz >= sizeof(msg));

	msg.magic = M_CLIENT_SIG;
	dh_write_rukey(&ec->dh, msg.gb);
	hash(sizeof(msg.gb), msg.gb, hv);
	asymm_sign(&ec->my_asymm, hv, msg.sig);

	memcpy(buf, &msg, sizeof(msg));
	ec->state = S_SESSION;
}

static struct ectun *ectun_new(void) {
	struct ectun *e = malloc(sizeof *e);
	if (!e)
		return NULL;
	e->flags = 0;
	dh_init(&e->dh);
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

struct ectun *ectun_new_server(char *spkey, ectun_keypred kc, void *arg) {
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
	hash_val hv;

	if (sz != sizeof(msg))
		return ECTUN_ERR_BADMSG;

	memcpy(&msg, buf, sz);
	hash(sizeof(msg.m), (void *)&msg.m, hv);
	asymm_read_ukey(&ec->their_asymm, msg.m.kcu);
	if (asymm_verify(&ec->their_asymm, hv, msg.sig))
		return ECTUN_ERR_BADMSG;
	dh_read_rukey(&ec->dh, msg.m.ga);
	hash(sizeof(msg.m.kcu), msg.m.kcu, ec->hkcu);
	ec->state = S_GOT_CLIENT_HELLO;
	return 0;
}

static int r_srvhello(struct ectun *ec, const unsigned char *buf, size_t sz) {
	struct m_server_hello msg;
	hash_val hv;
	dh_pubkey my_ukey;

	if (sz != sizeof(msg))
		return ECTUN_ERR_BADMSG;

	memcpy(&msg, buf, sz);
	hash(sizeof(msg.m), (void *)&msg.m, hv);
	if (asymm_verify(&ec->their_asymm, hv, msg.sig))
		return ECTUN_ERR_BADMSG;
	memset(my_ukey, 0, sizeof(my_ukey));
	dh_write_sukey(&ec->dh, my_ukey);
	if (memcmp(my_ukey, msg.m.ga, sizeof(my_ukey)))
		return ECTUN_ERR_BADMSG;
	dh_read_rukey(&ec->dh, msg.m.gb);
	dh_final(&ec->dh, ec->ke, ec->km);
	symm_init(&ec->send, ec->ke, 0);
	symm_init(&ec->recv, ec->ke, 1);
	ec->state = S_GOT_SERVER_HELLO;
	return 0;
}

static int r_clisig(struct ectun *ec, const unsigned char *buf, size_t sz) {
	struct m_client_sig msg;
	hash_val hv;
	dh_pubkey my_ukey;

	if (sz != sizeof(msg))
		return ECTUN_ERR_BADMSG;

	memcpy(&msg, buf, sz);
	hash(sizeof(msg.gb), (void *)&msg.gb, hv);
	if (asymm_verify(&ec->their_asymm, hv, msg.sig))
		return ECTUN_ERR_BADMSG;
	memset(my_ukey, 0, sizeof(my_ukey));
	dh_write_sukey(&ec->dh, my_ukey);
	if (memcmp(my_ukey, msg.gb, sizeof(my_ukey)))
		return ECTUN_ERR_BADMSG;

	dh_final(&ec->dh, ec->ke, ec->km);
	symm_init(&ec->send, ec->ke, 1);
	symm_init(&ec->recv, ec->ke, 0);
	ec->state = S_SESSION;
	return 0;
}

int ectun_needsinput(struct ectun *ec) {
	if (ec->flags & F_SERVER)
		return ec->state & SF_SERVER_IN;
	else
		return ec->state & SF_CLIENT_IN;
}

int ectun_input(struct ectun *ec, const unsigned char *buf, size_t sz) {
	/* This doesn't work on machines where sizeof(int) != 4 */
	unsigned int type;
	type = *(unsigned int *)buf;
	if (ec->flags & F_SERVER && type == M_CLIENT_HELLO)
		return r_clihello(ec, buf, sz);
	else if (ec->flags & F_SERVER && type == M_CLIENT_SIG)
		return r_clisig(ec, buf, sz);
	else if (!(ec->flags & F_SERVER) && type == M_SERVER_HELLO)
		return r_srvhello(ec, buf, sz);
	return ECTUN_ERR_BADMSG;
}

size_t ectun_hasoutput(struct ectun *ec) {
	if ((ec->flags & F_SERVER) && (ec->state & SF_SERVER_OUT)) {
		if (ec->state == S_GOT_CLIENT_HELLO)
			return sizeof(struct m_server_hello);
	} else if (!(ec->flags & F_SERVER) && (ec->state & SF_CLIENT_OUT)) {
		if (ec->state == S_NONE)
			return sizeof(struct m_client_hello);
		else if (ec->state == S_GOT_SERVER_HELLO)
			return sizeof(struct m_client_sig);
	}
	return 0;
}

void ectun_output(struct ectun *ec, unsigned char *buf, size_t sz) {
	if (ec->flags & F_SERVER && ec->state == S_GOT_CLIENT_HELLO)
		s_srvhello(ec, buf, sz);
	else if (!(ec->flags & F_SERVER) && ec->state == S_NONE)
		s_clihello(ec, buf, sz);
	else if (!(ec->flags & F_SERVER) && ec->state == S_GOT_SERVER_HELLO)
		s_clisig(ec, buf, sz);
}

ssize_t ectun_recv(struct ectun *ec, const unsigned char *inbuf, size_t sz, unsigned char *outbuf) {
	hmac_val hv;
	/* Messages on the wire are HMAC(Km, Es(Ke, b)) */
	assert(ec->state == S_SESSION);
	ec->state = S_NONE;
	hmac(ec->km, sz - sizeof(hmac_val), inbuf, hv);
	if (sz < sizeof(hmac_val))
		return ECTUN_ERR_BADMSG;
	if (!hmac_ok(ec->km, sz, inbuf))
		return ECTUN_ERR_HMACFAIL;
	sz -= sizeof(hmac_val);
	symm(&ec->recv, sz, inbuf, outbuf);
	ec->state = S_SESSION;
	return sz;
}

size_t ectun_sendsize(struct ectun *ec, size_t sz) {
	(void)ec;
	return sz + sizeof(hmac_val);
}

void ectun_send(struct ectun *ec, const unsigned char *inbuf, size_t sz, unsigned char *outbuf) {
	assert(ec->state == S_SESSION);
	symm(&ec->send, sz, inbuf, outbuf);
	hmac(ec->km, sz, outbuf, outbuf + sz);
}
