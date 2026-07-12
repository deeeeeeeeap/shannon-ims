/*
 * See p_cscf_vohive_handler.h. Wire format is documented in
 * ../bridge.go's readPush and must be kept in sync with it: a fixed
 * one-shot push, not a request/response (there's nothing for the plugin to
 * ask the Go side for -- charon tells us something it learned, once, when
 * it learns it).
 *
 * handle()/release()/create_attribute_enumerator() are modeled directly on
 * strongSwan's own stock p_cscf_handler.c, with one deliberate
 * simplification: the stock handler only asks for P-CSCF addresses on
 * connections explicitly enabled via `charon.plugins.p-cscf.enable.<conn>`
 * (it's meant to coexist with non-IMS connections in a general-purpose
 * charon). vohive's charon instance never carries anything other than SWu
 * VoWiFi tunnels, so every IKEv2 connection should request P-CSCF
 * addresses unconditionally -- there is no "some connections want this,
 * some don't" case here, so the settings-gate is dropped rather than
 * templating a per-connection-name strongswan.conf fragment for a
 * dynamically-named connection (connNameFor(deviceID) in ../../conn.go).
 */

#include "p_cscf_vohive_handler.h"

#include <daemon.h>
#include <networking/host.h>
#include <utils/debug.h>

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

typedef struct private_p_cscf_vohive_handler_t private_p_cscf_vohive_handler_t;

/* Wire protocol constants -- must match engine/swu/pcscfbridge/bridge.go. */
#define PROTO_VERSION    1
#define FAMILY_IPV4      4
#define FAMILY_IPV6      6
#define MAX_CONN_NAME_LEN 255

struct private_p_cscf_vohive_handler_t {

	/**
	 * Public interface
	 */
	p_cscf_vohive_handler_t public;

	/**
	 * Path to the pcscfbridge Unix socket.
	 */
	char *socket_path;
};

/**
 * Push connName + the P-CSCF address to the Go pcscfbridge. Best-effort:
 * if the bridge is unreachable or the write fails, this only logs -- the
 * IKE_SA itself must not be torn down over a discovery-plumbing failure,
 * same reasoning as the AKA card's exchange() being the only thing that
 * can fail an authentication, not this.
 */
static void push(private_p_cscf_vohive_handler_t *this, const char *conn_name,
				  int family, chunk_t addr)
{
	int fd;
	struct sockaddr_un saddr;
	uint8_t buf[2 + MAX_CONN_NAME_LEN + 1 + 16];
	size_t name_len, len;

	name_len = strlen(conn_name);
	if (name_len > MAX_CONN_NAME_LEN)
	{
		name_len = MAX_CONN_NAME_LEN;
	}

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
	{
		DBG1(DBG_CFG, "vohive-pcscf: socket() failed: %s", strerror(errno));
		return;
	}

	memset(&saddr, 0, sizeof(saddr));
	saddr.sun_family = AF_UNIX;
	strncpy(saddr.sun_path, this->socket_path, sizeof(saddr.sun_path) - 1);

	if (connect(fd, (struct sockaddr*)&saddr, sizeof(saddr)) < 0)
	{
		DBG1(DBG_CFG, "vohive-pcscf: connect(%s) failed: %s",
			 this->socket_path, strerror(errno));
		close(fd);
		return;
	}

	buf[0] = PROTO_VERSION;
	buf[1] = (uint8_t)name_len;
	memcpy(buf + 2, conn_name, name_len);
	buf[2 + name_len] = (uint8_t)family;
	memcpy(buf + 2 + name_len + 1, addr.ptr, addr.len);
	len = 2 + name_len + 1 + addr.len;

	if (write(fd, buf, len) != (ssize_t)len)
	{
		DBG1(DBG_CFG, "vohive-pcscf: short write to bridge: %s", strerror(errno));
	}
	close(fd);
}

METHOD(attribute_handler_t, handle, bool,
	private_p_cscf_vohive_handler_t *this, ike_sa_t *ike_sa,
	configuration_attribute_type_t type, chunk_t data)
{
	host_t *server;
	int family = AF_INET6, wire_family = FAMILY_IPV6;

	switch (type)
	{
		case P_CSCF_IP4_ADDRESS:
			family = AF_INET;
			wire_family = FAMILY_IPV4;
			/* fall-through */
		case P_CSCF_IP6_ADDRESS:
			server = host_create_from_chunk(family, data, 0);
			if (!server)
			{
				DBG1(DBG_CFG, "vohive-pcscf: received invalid P-CSCF server IP");
				return FALSE;
			}
			DBG1(DBG_CFG, "vohive-pcscf: received P-CSCF server IP %H", server);
			push(this, ike_sa->get_name(ike_sa), wire_family, data);
			server->destroy(server);
			return TRUE;
		default:
			return FALSE;
	}
}

METHOD(attribute_handler_t, release, void,
	private_p_cscf_vohive_handler_t *this, ike_sa_t *ike_sa,
	configuration_attribute_type_t type, chunk_t data)
{
	switch (type)
	{
		case P_CSCF_IP4_ADDRESS:
		case P_CSCF_IP6_ADDRESS:
			/* nothing to do: the address was already pushed to the Go side
			 * as soon as it was learned, and doesn't change mid-session. */
			break;
		default:
			break;
	}
}

/**
 * Data for attribute enumerator
 */
typedef struct {
	enumerator_t public;
	bool request_ipv4;
	bool request_ipv6;
} attr_enumerator_t;

METHOD(enumerator_t, enumerate_attrs, bool,
	attr_enumerator_t *this, va_list args)
{
	configuration_attribute_type_t *type;
	chunk_t *data;

	VA_ARGS_VGET(args, type, data);
	if (this->request_ipv4)
	{
		*type = P_CSCF_IP4_ADDRESS;
		*data = chunk_empty;
		this->request_ipv4 = FALSE;
		return TRUE;
	}
	if (this->request_ipv6)
	{
		*type = P_CSCF_IP6_ADDRESS;
		*data = chunk_empty;
		this->request_ipv6 = FALSE;
		return TRUE;
	}
	return FALSE;
}

CALLBACK(is_family, bool,
	host_t *host, va_list args)
{
	int family;

	VA_ARGS_VGET(args, family);
	return host->get_family(host) == family;
}

/**
 * Check if a list has a host of a given family
 */
static bool has_host_family(linked_list_t *list, int family)
{
	return list->find_first(list, is_family, NULL, family);
}

METHOD(attribute_handler_t, create_attribute_enumerator, enumerator_t *,
	private_p_cscf_vohive_handler_t *this, ike_sa_t *ike_sa,
	linked_list_t *vips)
{
	attr_enumerator_t *enumerator;

	if (ike_sa->get_version(ike_sa) == IKEV1)
	{
		return enumerator_create_empty();
	}

	INIT(enumerator,
		.public = {
			.enumerate = enumerator_enumerate_default,
			.venumerate = _enumerate_attrs,
			.destroy = (void*)free,
		},
	);
	/* Unlike the stock p-cscf plugin, no per-connection-name settings gate:
	 * every SWu connection this charon instance ever loads is a VoWiFi
	 * tunnel that wants its P-CSCF address, so request it whenever a vip of
	 * the matching family was requested at all (see this file's header
	 * comment for why). */
	enumerator->request_ipv4 = has_host_family(vips, AF_INET);
	enumerator->request_ipv6 = has_host_family(vips, AF_INET6);
	return &enumerator->public;
}

METHOD(p_cscf_vohive_handler_t, destroy, void,
	private_p_cscf_vohive_handler_t *this)
{
	free(this->socket_path);
	free(this);
}

/**
 * See header
 */
p_cscf_vohive_handler_t *p_cscf_vohive_handler_create(const char *socket_path)
{
	private_p_cscf_vohive_handler_t *this;

	INIT(this,
		.public = {
			.handler = {
				.handle = _handle,
				.release = _release,
				.create_attribute_enumerator = _create_attribute_enumerator,
			},
			.destroy = _destroy,
		},
		.socket_path = strdup(socket_path),
	);

	return &this->public;
}
