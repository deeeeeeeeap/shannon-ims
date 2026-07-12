/*
 * See p_cscf_vohive_handler.h for what this plugin does.
 */

#ifndef P_CSCF_VOHIVE_PLUGIN_H_
#define P_CSCF_VOHIVE_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct p_cscf_vohive_plugin_t p_cscf_vohive_plugin_t;

/**
 * Plugin that requests P-CSCF server addresses from an ePDG as specified
 * in RFC 7651, and forwards whatever it receives to the Go pcscfbridge.
 */
struct p_cscf_vohive_plugin_t {

	/**
	 * Implements plugin interface.
	 */
	plugin_t plugin;
};

#endif /** P_CSCF_VOHIVE_PLUGIN_H_ */
