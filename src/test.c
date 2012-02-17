#include <stdio.h>
#include <string.h>

#include "crypto.h"
#include "ectun.h"

static int kp(char *h, void *arg) {
	printf("ok? %s\n", h);
	return 1;
}

int main(void) {
	ectun_ukey sukey;
	ectun_pkey spkey;
	ectun_ukey cukey;
	ectun_pkey cpkey;
	struct ectun *cec;
	struct ectun *sec;
	ssize_t sz;
	unsigned char buf0[4096];
	unsigned char buf1[4096];
	unsigned char msg0[] = "Hello, server!";
	unsigned char msg1[] = "Hello, client!";

	hmac_key k;
	char buf[128];
	buf[0] = 0xda;
	buf[1] = 0x70;
	hmac(k, 2, buf, buf + 2);
	printf("%d\n", hmac_ok(k, 2 + sizeof(hmac_val), buf));

	printf("gen\n");
	ectun_genkey(&sukey, &spkey);
	printf("skey\n");
	ectun_genkey(&cukey, &cpkey);
	printf("ckey\n");

	cec = ectun_new_client(sukey, cpkey);
	sec = ectun_new_server(spkey, kp, NULL);

	sz = ectun_hasoutput(cec);
	printf("c->s %zub\n", sz);
	ectun_output(cec, buf0, sizeof(buf0));
	ectun_input(sec, buf0, sz);

	sz = ectun_hasoutput(sec);
	printf("s->c %zub\n", sz);
	ectun_output(sec, buf1, sizeof(buf1));
	ectun_input(cec, buf1, sz);

	sz = ectun_hasoutput(cec);
	printf("c->s %zub\n", sz);
	ectun_output(cec, buf0, sizeof(buf0));
	ectun_input(sec, buf0, sz);

	sz = ectun_sendsize(cec, sizeof(msg0));
	ectun_send(cec, msg0, sizeof(msg0), buf0);
	sz = ectun_recv(sec, buf0, sz, buf1);
	printf("c->s %p\n", buf1);

	sz = ectun_sendsize(sec, sizeof(msg1));
	ectun_send(sec, msg1, sizeof(msg1), buf0);
	sz = ectun_recv(cec, buf0, sz, buf1);
	printf("s->c %p\n", buf1);

	printf("ok\n");
	
	return 0;
}
