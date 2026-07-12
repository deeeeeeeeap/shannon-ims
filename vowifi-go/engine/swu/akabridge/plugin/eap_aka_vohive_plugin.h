/*
 * See eap_aka_vohive_card.h for what this plugin does.
 */

#ifndef EAP_AKA_VOHIVE_PLUGIN_H_
#define EAP_AKA_VOHIVE_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct eap_aka_vohive_plugin_t eap_aka_vohive_plugin_t;

/**
 * Plugin registering an AKA card backed by the Go akabridge.
 */
struct eap_aka_vohive_plugin_t {

	/**
	 * Implements plugin_t interface.
	 */
	plugin_t plugin;
};

#endif /** EAP_AKA_VOHIVE_PLUGIN_H_ */
