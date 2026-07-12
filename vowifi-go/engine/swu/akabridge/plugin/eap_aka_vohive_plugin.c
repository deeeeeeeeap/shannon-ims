/*
 * See eap_aka_vohive_card.h for what this plugin does. Registration follows
 * the exact same simaka_manager_register / PLUGIN_CALLBACK pattern as
 * strongSwan's own eap-sim-pcsc plugin (libcharon/plugins/eap_sim_pcsc) --
 * that plugin is the reference this one is modeled on, just replacing its
 * PC/SC reader I/O with the Go bridge's Unix socket.
 */

#include "eap_aka_vohive_plugin.h"
#include "eap_aka_vohive_card.h"

#include <daemon.h>

/**
 * Default akabridge socket path. Matches the /run/charon.* pattern already
 * whitelisted by the stock Debian/Ubuntu AppArmor profile for charon (see
 * engine/swu/charon's package doc comment for how that was found).
 * Overridable via `charon.plugins.eap-aka-vohive.socket` for systems without
 * that confinement.
 */
#ifndef VOHIVE_AKA_DEFAULT_SOCKET
#define VOHIVE_AKA_DEFAULT_SOCKET "/run/charon.vohive-aka"
#endif

typedef struct private_eap_aka_vohive_plugin_t private_eap_aka_vohive_plugin_t;

struct private_eap_aka_vohive_plugin_t {

	/**
	 * Public interface.
	 */
	eap_aka_vohive_plugin_t public;

	/**
	 * The AKA card registered with the simaka manager.
	 */
	eap_aka_vohive_card_t *card;
};

METHOD(plugin_t, get_name, char*,
	private_eap_aka_vohive_plugin_t *this)
{
	return "eap-aka-vohive";
}

/**
 * Callback providing our card to register.
 */
static simaka_card_t* get_card(private_eap_aka_vohive_plugin_t *this)
{
	return &this->card->card;
}

METHOD(plugin_t, get_features, int,
	private_eap_aka_vohive_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK(simaka_manager_register, get_card),
			PLUGIN_PROVIDE(CUSTOM, "aka-card"),
				PLUGIN_DEPENDS(CUSTOM, "aka-manager"),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_eap_aka_vohive_plugin_t *this)
{
	this->card->destroy(this->card);
	free(this);
}

/*
 * See header.
 */
plugin_t *eap_aka_vohive_plugin_create()
{
	private_eap_aka_vohive_plugin_t *this;
	char *socket_path;

	socket_path = lib->settings->get_str(lib->settings,
					"%s.plugins.eap-aka-vohive.socket",
					VOHIVE_AKA_DEFAULT_SOCKET, lib->ns);

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.destroy = _destroy,
			},
		},
		.card = eap_aka_vohive_card_create(socket_path),
	);

	return &this->public.plugin;
}
