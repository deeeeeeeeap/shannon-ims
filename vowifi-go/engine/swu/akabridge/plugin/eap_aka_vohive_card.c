/*
 * See eap_aka_vohive_card.h. Wire format is documented in ../bridge.go and
 * must be kept in sync with it; both sides are hand-rolled on purpose (the
 * payloads are tiny and fixed-size, not worth a serialization dependency on
 * either the C or the Go side).
 */

#include "eap_aka_vohive_card.h"

#include <daemon.h>
#include <collections/linked_list.h>
#include <threading/mutex.h>

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

typedef struct private_eap_aka_vohive_card_t private_eap_aka_vohive_card_t;

/* Wire protocol constants -- must match engine/swu/akabridge/bridge.go. */
#define PROTO_VERSION       1
#define STATUS_SUCCESS      0
#define STATUS_SYNC_FAILURE 1
#define STATUS_FAILED       2
#define STATUS_NOT_FOUND    3
#define MAX_IDENTITY_LEN    255

struct private_eap_aka_vohive_card_t {

	/**
	 * Public interface.
	 */
	eap_aka_vohive_card_t public;

	/**
	 * Path to the akabridge Unix socket.
	 */
	char *socket_path;

	/**
	 * Guards auts_cache.
	 */
	mutex_t *mutex;

	/**
	 * AUTS values from a prior get_quintuplet sync failure, keyed by
	 * identity, so the resync() call charon makes right after can answer
	 * without a second round trip. Entries of type auts_entry_t.
	 */
	linked_list_t *auts_cache;
};

typedef struct {
	char id[MAX_IDENTITY_LEN + 1];
	char auts[AKA_AUTS_LEN];
} auts_entry_t;

/**
 * Format an identification_t as the same identity string the Go side keys
 * its provider registry by (the NAI/IMPI used as the EAP identity).
 */
static int format_identity(identification_t *id, char *buf, size_t buflen)
{
	return snprintf(buf, buflen, "%Y", id);
}

/**
 * Dial the bridge, send one request, read the response.
 *
 * Returns TRUE if the round trip itself completed (a connection plus a full
 * request/response exchange) -- NOT whether the AKA computation succeeded;
 * *status carries that. FALSE means the bridge is unreachable or the
 * response was malformed, which callers must treat as FAILED, not as
 * "identity not found".
 */
static bool exchange(private_eap_aka_vohive_card_t *this,
					  const char *id, size_t id_len,
					  char rand[AKA_RAND_LEN], char autn[AKA_AUTN_LEN],
					  uint8_t *status, char *payload, size_t *payload_len)
{
	int fd;
	struct sockaddr_un addr;
	uint8_t req[2 + MAX_IDENTITY_LEN + AKA_RAND_LEN + AKA_AUTN_LEN];
	size_t req_len;
	ssize_t n;
	uint8_t resp[1 + 1 + AKA_RES_MAX + AKA_CK_LEN + AKA_IK_LEN];

	if (id_len > MAX_IDENTITY_LEN)
	{
		id_len = MAX_IDENTITY_LEN;
	}

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
	{
		DBG1(DBG_IKE, "vohive-aka: socket() failed: %s", strerror(errno));
		return FALSE;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, this->socket_path, sizeof(addr.sun_path) - 1);

	if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
	{
		DBG1(DBG_IKE, "vohive-aka: connect(%s) failed: %s",
			 this->socket_path, strerror(errno));
		close(fd);
		return FALSE;
	}

	req[0] = PROTO_VERSION;
	req[1] = (uint8_t)id_len;
	memcpy(req + 2, id, id_len);
	memcpy(req + 2 + id_len, rand, AKA_RAND_LEN);
	memcpy(req + 2 + id_len + AKA_RAND_LEN, autn, AKA_AUTN_LEN);
	req_len = 2 + id_len + AKA_RAND_LEN + AKA_AUTN_LEN;

	if (write(fd, req, req_len) != (ssize_t)req_len)
	{
		DBG1(DBG_IKE, "vohive-aka: short write to bridge: %s", strerror(errno));
		close(fd);
		return FALSE;
	}

	n = read(fd, resp, sizeof(resp));
	close(fd);

	if (n < 1)
	{
		DBG1(DBG_IKE, "vohive-aka: no response from bridge (n=%zd)", n);
		return FALSE;
	}

	*status = resp[0];
	switch (*status)
	{
		case STATUS_SUCCESS:
		{
			size_t res_len;

			if (n < 2)
			{
				return FALSE;
			}
			res_len = resp[1];
			if (res_len > AKA_RES_MAX ||
				(size_t)n < 2 + res_len + AKA_CK_LEN + AKA_IK_LEN)
			{
				DBG1(DBG_IKE, "vohive-aka: malformed success response "
					 "(res_len=%zu n=%zd)", res_len, n);
				return FALSE;
			}
			memcpy(payload, resp + 2, res_len + AKA_CK_LEN + AKA_IK_LEN);
			*payload_len = res_len;
			break;
		}
		case STATUS_SYNC_FAILURE:
			if ((size_t)n < 1 + AKA_AUTS_LEN)
			{
				DBG1(DBG_IKE, "vohive-aka: malformed sync-failure response "
					 "(n=%zd)", n);
				return FALSE;
			}
			memcpy(payload, resp + 1, AKA_AUTS_LEN);
			break;
		case STATUS_FAILED:
		case STATUS_NOT_FOUND:
			break;
		default:
			DBG1(DBG_IKE, "vohive-aka: unknown response status %u", *status);
			return FALSE;
	}
	return TRUE;
}

/**
 * Remember auts for id, replacing any previous entry -- there's only ever
 * one in-flight AKA exchange per identity, so a single cached value per id
 * is sufficient.
 */
static void cache_auts(private_eap_aka_vohive_card_t *this,
						const char *idbuf, char auts[AKA_AUTS_LEN])
{
	enumerator_t *enumerator;
	auts_entry_t *entry;
	bool found = FALSE;

	this->mutex->lock(this->mutex);

	enumerator = this->auts_cache->create_enumerator(this->auts_cache);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (streq(entry->id, idbuf))
		{
			memcpy(entry->auts, auts, AKA_AUTS_LEN);
			found = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);

	if (!found)
	{
		size_t idlen = strnlen(idbuf, sizeof(entry->id) - 1);

		entry = malloc(sizeof(auts_entry_t));
		memset(entry, 0, sizeof(*entry));
		memcpy(entry->id, idbuf, idlen);
		memcpy(entry->auts, auts, AKA_AUTS_LEN);
		this->auts_cache->insert_last(this->auts_cache, entry);
	}

	this->mutex->unlock(this->mutex);
}

METHOD(simaka_card_t, get_quintuplet, status_t,
	private_eap_aka_vohive_card_t *this, identification_t *id,
	char rand[AKA_RAND_LEN], char autn[AKA_AUTN_LEN],
	char ck[AKA_CK_LEN], char ik[AKA_IK_LEN],
	char res[AKA_RES_MAX], int *res_len)
{
	char idbuf[MAX_IDENTITY_LEN + 1];
	int idlen;
	uint8_t status;
	char payload[AKA_RES_MAX + AKA_CK_LEN + AKA_IK_LEN];
	size_t payload_len = 0;

	idlen = format_identity(id, idbuf, sizeof(idbuf));
	if (idlen < 0)
	{
		return FAILED;
	}

	if (!exchange(this, idbuf, (size_t)idlen, rand, autn,
				  &status, payload, &payload_len))
	{
		return FAILED;
	}

	switch (status)
	{
		case STATUS_SUCCESS:
			memcpy(res, payload, payload_len);
			*res_len = (int)payload_len;
			memcpy(ck, payload + payload_len, AKA_CK_LEN);
			memcpy(ik, payload + payload_len + AKA_CK_LEN, AKA_IK_LEN);
			return SUCCESS;
		case STATUS_SYNC_FAILURE:
			cache_auts(this, idbuf, payload);
			return INVALID_STATE;
		case STATUS_NOT_FOUND:
			DBG1(DBG_IKE, "vohive-aka: no AKA provider registered for %Y", id);
			return FAILED;
		default:
			return FAILED;
	}
}

METHOD(simaka_card_t, resync, bool,
	private_eap_aka_vohive_card_t *this, identification_t *id,
	char rand[AKA_RAND_LEN], char auts[AKA_AUTS_LEN])
{
	char idbuf[MAX_IDENTITY_LEN + 1];
	enumerator_t *enumerator;
	auts_entry_t *entry;
	bool found = FALSE;

	format_identity(id, idbuf, sizeof(idbuf));

	this->mutex->lock(this->mutex);
	enumerator = this->auts_cache->create_enumerator(this->auts_cache);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (streq(entry->id, idbuf))
		{
			memcpy(auts, entry->auts, AKA_AUTS_LEN);
			found = TRUE;
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->mutex->unlock(this->mutex);

	if (!found)
	{
		DBG1(DBG_IKE, "vohive-aka: resync requested for %Y but no cached "
			 "AUTS (get_quintuplet should always precede resync)", id);
	}
	return found;
}

METHOD(eap_aka_vohive_card_t, destroy, void,
	private_eap_aka_vohive_card_t *this)
{
	this->auts_cache->destroy_function(this->auts_cache, free);
	this->mutex->destroy(this->mutex);
	free(this->socket_path);
	free(this);
}

eap_aka_vohive_card_t *eap_aka_vohive_card_create(const char *socket_path)
{
	private_eap_aka_vohive_card_t *this;

	INIT(this,
		.public = {
			.card = {
				.get_triplet = (void*)return_false,
				.get_quintuplet = _get_quintuplet,
				.resync = _resync,
				.get_pseudonym = (void*)return_null,
				.set_pseudonym = (void*)nop,
				.get_reauth = (void*)return_null,
				.set_reauth = (void*)nop,
			},
			.destroy = _destroy,
		},
		.socket_path = strdup(socket_path),
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.auts_cache = linked_list_create(),
	);

	return &this->public;
}
