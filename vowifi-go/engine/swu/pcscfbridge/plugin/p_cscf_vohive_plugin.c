/*
 * See p_cscf_vohive_handler.h for what this plugin does. Registration
 * follows the exact same attribute_handler_t / PLUGIN_CALLBACK pattern as
 * strongSwan's own stock p_cscf plugin (libcharon/plugins/p_cscf) -- that
 * plugin is the reference this one is modeled on, just forwarding the
 * received address to the Go pcscfbridge instead of only logging it.
 */

#include "p_cscf_vohive_plugin.h"
#include "p_cscf_vohive_handler.h"

#include <daemon.h>

/**
 * Default pcscfbridge socket path. Matches the /run/charon.* pattern
 * already whitelisted by the stock Debian/Ubuntu AppArmor profile for
 * charon (see engine/swu/charon's package doc comment for how that was
 * found). Overridable via `charon.plugins.p-cscf-vohive.socket` for
 * systems without that confinement.
 */
#ifndef VOHIVE_PCSCF_DEFAULT_SOCKET
#define VOHIVE_PCSCF_DEFAULT_SOCKET "/run/charon.vohive-pcscf"
#endif

typedef struct private_p_cscf_vohive_plugin_t private_p_cscf_vohive_plugin_t;

/**
 * Private data
 */
struct private_p_cscf_vohive_plugin_t {

	/**
	 * Public interface
	 */
	p_cscf_vohive_plugin_t public;

	/**
	 * P-CSCF server address attribute handler
	 */
	p_cscf_vohive_handler_t *handler;
};

METHOD(plugin_t, get_name, char*,
	private_p_cscf_vohive_plugin_t *this)
{
	return "p-cscf-vohive";
}

/**
 * Register/unregister the handler with charon's attribute_manager.
 */
static bool plugin_cb(private_p_cscf_vohive_plugin_t *this,
					  plugin_feature_t *feature, bool reg, void *cb_data)
{
	if (reg)
	{
		charon->attributes->add_handler(charon->attributes,
										&this->handler->handler);
	}
	else
	{
		charon->attributes->remove_handler(charon->attributes,
										   &this->handler->handler);
	}
	return TRUE;
}

METHOD(plugin_t, get_features, int,
	private_p_cscf_vohive_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK((plugin_feature_callback_t)plugin_cb, NULL),
			PLUGIN_PROVIDE(CUSTOM, "p-cscf-vohive"),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_p_cscf_vohive_plugin_t *this)
{
	this->handler->destroy(this->handler);
	free(this);
}

/**
 * See header
 */
plugin_t *p_cscf_vohive_plugin_create()
{
	private_p_cscf_vohive_plugin_t *this;
	char *socket_path;

	socket_path = lib->settings->get_str(lib->settings,
					"%s.plugins.p-cscf-vohive.socket",
					VOHIVE_PCSCF_DEFAULT_SOCKET, lib->ns);

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.destroy = _destroy,
			},
		},
		.handler = p_cscf_vohive_handler_create(socket_path),
	);

	return &this->public.plugin;
}
