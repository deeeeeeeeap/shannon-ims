/*
 * Standalone test harness for eap_aka_vohive_card_t. Bypasses charon and IKE
 * entirely: calls get_quintuplet/resync directly against a real
 * akabridgetest Go process (spike/akabridgetest), using fixed test vectors
 * on both ends. This is what actually validates the new artifact (the C
 * plugin <-> Go bridge wire protocol) -- the vici control surface and
 * tunnel plumbing were already validated separately and don't need
 * re-proving here.
 *
 * Run: start `akabridgetest <socket>` first, then this binary with the same
 * socket path as argv[1].
 */

#include <library.h>
#include <simaka_manager.h>
#include "../eap_aka_vohive_card.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond, msg) do { \
		if (!(cond)) { \
			printf("FAIL: %s\n", msg); \
			failures++; \
		} else { \
			printf("ok:   %s\n", msg); \
		} \
	} while (0)

static int hex_eq(const char *label, const char *got, const char *want, size_t len)
{
	if (memcmp(got, want, len) == 0)
	{
		printf("ok:   %s matches\n", label);
		return 1;
	}
	printf("FAIL: %s mismatch\n", label);
	failures++;
	return 0;
}

int main(int argc, char *argv[])
{
	eap_aka_vohive_card_t *card;
	identification_t *registered_id, *unknown_id;
	char rand_buf[AKA_RAND_LEN];
	char autn_buf[AKA_AUTN_LEN];
	char ck[AKA_CK_LEN], ik[AKA_IK_LEN], res[AKA_RES_MAX], auts[AKA_AUTS_LEN];
	int res_len;
	status_t status;
	bool ok;

	static const char want_res[] = { 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 };
	static const char want_ck[AKA_CK_LEN] = {
		0x21,0x21,0x21,0x21,0x21,0x21,0x21,0x21,0x21,0x21,0x21,0x21,0x21,0x21,0x21,0x21
	};
	static const char want_ik[AKA_IK_LEN] = {
		0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22
	};
	static const char want_auts[AKA_AUTS_LEN] = {
		0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33
	};

	if (argc < 2)
	{
		fprintf(stderr, "usage: %s <akabridge-socket-path>\n", argv[0]);
		return 2;
	}

	library_init("", "card_test");
	atexit(library_deinit);

	card = eap_aka_vohive_card_create(argv[1]);

	registered_id = identification_create_from_string("test@vohive");
	unknown_id = identification_create_from_string("nobody@vohive");

	/* --- 1. success path --- */
	memset(rand_buf, 0xAA, sizeof(rand_buf));
	memset(autn_buf, 0xBB, sizeof(autn_buf));
	memset(ck, 0, sizeof(ck));
	memset(ik, 0, sizeof(ik));
	memset(res, 0, sizeof(res));
	res_len = 0;

	status = card->card.get_quintuplet(&card->card, registered_id,
			rand_buf, autn_buf, ck, ik, res, &res_len);

	CHECK(status == SUCCESS, "get_quintuplet returns SUCCESS for a registered identity");
	CHECK(res_len == (int)sizeof(want_res), "RES length matches");
	if (res_len == (int)sizeof(want_res))
	{
		hex_eq("RES", res, want_res, sizeof(want_res));
	}
	hex_eq("CK", ck, want_ck, sizeof(want_ck));
	hex_eq("IK", ik, want_ik, sizeof(want_ik));

	/* --- 2. sync failure + resync path (RAND[0] == 0xFF is the trigger) --- */
	memset(rand_buf, 0, sizeof(rand_buf));
	rand_buf[0] = (char)0xFF;
	memset(autn_buf, 0xCC, sizeof(autn_buf));
	memset(ck, 0, sizeof(ck));
	memset(ik, 0, sizeof(ik));
	memset(res, 0, sizeof(res));
	res_len = 0;

	status = card->card.get_quintuplet(&card->card, registered_id,
			rand_buf, autn_buf, ck, ik, res, &res_len);
	CHECK(status == INVALID_STATE, "get_quintuplet returns INVALID_STATE on sync failure");

	memset(auts, 0, sizeof(auts));
	ok = card->card.resync(&card->card, registered_id, rand_buf, auts);
	CHECK(ok, "resync succeeds after a preceding sync-failure get_quintuplet");
	hex_eq("AUTS", auts, want_auts, sizeof(want_auts));

	/* --- 3. unknown identity --- */
	memset(rand_buf, 0x01, sizeof(rand_buf));
	memset(autn_buf, 0x02, sizeof(autn_buf));
	res_len = 0;
	status = card->card.get_quintuplet(&card->card, unknown_id,
			rand_buf, autn_buf, ck, ik, res, &res_len);
	CHECK(status == FAILED, "get_quintuplet returns FAILED for an unregistered identity");

	registered_id->destroy(registered_id);
	unknown_id->destroy(unknown_id);
	card->destroy(card);

	printf("\n%s\n", failures == 0 ? "ALL PASS" : "SOME FAILED");
	return failures == 0 ? 0 : 1;
}
