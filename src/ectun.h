/* ectun.h */

#ifndef ECTUN_H
#define ECTUN_H

#include <stddef.h>

typedef char *ectun_pkey;
typedef char *ectun_ukey;
typedef char *ectun_hash;
typedef int (*ectun_keypred)(ectun_hash hash, void *arg);

enum {
	ECTUN_ERR_NONE = 0,
	ECTUN_ERR_NOMEM = -1,
	ECTUN_ERR_BADMSG = -2,
	ECTUN_ERR_ACCESS = -3,
	ECTUN_ERR_HMACFAIL = -4,
	ECTUN_ERR_DECRYPT = -5,
	ECTUN_ERR_IO = -6,
	ECTUN_ERR_BADKEY = -7,
};

struct ectun;

int ectun_genkey(ectun_ukey *ukey, ectun_pkey *pkey);

struct ectun *ectun_new_client(ectun_ukey skey, ectun_pkey ckey);
struct ectun *ectun_new_server(ectun_pkey skey, ectun_keypred *kc, void *arg);

int ectun_needsinput(struct ectun *ec);
int ectun_input(struct ectun *ec, const unsigned char *buf, size_t sz);
size_t ectun_hasoutput(struct ectun *ec);
void ectun_output(struct ectun *ec, unsigned char *buf, size_t sz);

ssize_t ectun_recv(struct ectun *ec, const unsigned char *input, size_t sz,
                   unsigned char *outbuf);
size_t ectun_sendsize(struct ectun *ec, size_t sz);
void ectun_send(struct ectun *ec, const unsigned char *inbuf, size_t sz,
                unsigned char *outbuf);

int ectun_issession(struct ectun *ec);

#endif /* !ECTUN_H */
