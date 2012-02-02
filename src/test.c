#include <stdio.h>
#include <string.h>

#include "crypto.h"
#include "ectun.h"

int main(void) {
	struct dh_ctx s;
	struct dh_ctx c;
	char *cu;
	char *su;
	symm_key kes;
	hmac_key kms;
	symm_key kec;
	hmac_key kmc;

	printf("ci %d\n", dh_init(&c));
	printf("si %d\n", dh_init(&s));
	cu = dh_ukey(&c);
	su = dh_ukey(&s);
	printf("cg %d\n", dh_got(&c, su));
	printf("sg %d\n", dh_got(&s, cu));
	printf("cf %d\n", dh_final(&c, kec, kmc));
	printf("sf %d\n", dh_final(&s, kes, kms));

	if (memcmp(kes, kec, sizeof(kes)))
		printf("ke mismatch\n");
	if (memcmp(kms, kmc, sizeof(kms)))
		printf("km mismatch\n");
	return 0;
}
