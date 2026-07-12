/*
 * eap_aka_vohive: bridges strongSwan's EAP-AKA card interface to a live
 * QMI/APDU-backed SIM via the Go akabridge Unix socket server. See
 * ../bridge.go for the wire format and the reasoning (strongSwan's stock
 * EAP-AKA card backends only support a PC/SC reader or static test vectors;
 * neither fits a SIM behind a QMI modem).
 *
 * Not part of the vowifi-go Go module — a separate build artifact, a shared
 * library loaded by charon via dlopen, same as any other strongSwan plugin.
 */

#ifndef EAP_AKA_VOHIVE_CARD_H_
#define EAP_AKA_VOHIVE_CARD_H_

#include <simaka_card.h>

typedef struct eap_aka_vohive_card_t eap_aka_vohive_card_t;

/**
 * AKA card implementation that forwards get_quintuplet/resync to the Go
 * akabridge over a Unix socket, rather than a local smartcard.
 */
struct eap_aka_vohive_card_t {

	/**
	 * Implements simaka_card_t interface.
	 */
	simaka_card_t card;

	/**
	 * Destroy a eap_aka_vohive_card_t.
	 */
	void (*destroy)(eap_aka_vohive_card_t *this);
};

/**
 * Create an eap_aka_vohive_card instance.
 *
 * @param socket_path	path of the akabridge Unix socket to dial per request
 */
eap_aka_vohive_card_t *eap_aka_vohive_card_create(const char *socket_path);

#endif /** EAP_AKA_VOHIVE_CARD_H_ */
