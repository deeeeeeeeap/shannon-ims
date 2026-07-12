/*
 * p_cscf_vohive: forwards the P-CSCF server address strongSwan's IKE_AUTH
 * configuration payload received to the Go pcscfbridge over a Unix socket,
 * keyed by the vici connection name (ike_sa->get_name()). Modeled directly
 * on strongSwan's own libcharon/plugins/p_cscf, which implements the same
 * attribute_handler_t interface but only logs the address — there's no
 * vici surface for it at all, same class of gap that motivated
 * engine/swu/akabridge for EAP-AKA.
 *
 * Not part of the vowifi-go Go module — a separate build artifact, a shared
 * library loaded by charon via dlopen, same as any other strongSwan plugin.
 */

#ifndef P_CSCF_VOHIVE_HANDLER_H_
#define P_CSCF_VOHIVE_HANDLER_H_

#include <attributes/attribute_handler.h>

typedef struct p_cscf_vohive_handler_t p_cscf_vohive_handler_t;

/**
 * Attribute handler for P-CSCF server addresses that forwards to the Go
 * pcscfbridge instead of just logging.
 */
struct p_cscf_vohive_handler_t {

	/**
	 * Implements attribute_handler_t interface.
	 */
	attribute_handler_t handler;

	/**
	 * Destroy a p_cscf_vohive_handler_t.
	 */
	void (*destroy)(p_cscf_vohive_handler_t *this);
};

/**
 * Create a p_cscf_vohive_handler_t instance.
 *
 * @param socket_path	path of the pcscfbridge Unix socket to push to
 */
p_cscf_vohive_handler_t *p_cscf_vohive_handler_create(const char *socket_path);

#endif /** P_CSCF_VOHIVE_HANDLER_H_ */
