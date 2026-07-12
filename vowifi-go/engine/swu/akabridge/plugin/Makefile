# Builds libstrongswan-eap-aka-vohive.so, the C plugin bridging charon's
# EAP-AKA card interface to the Go akabridge (see bridge.go one level up).
#
# Not part of `go build` on purpose: strongSwan doesn't ship a -dev/headers
# package, so this compiles against the actual strongSwan source tree for
# the *installed* version (get it with `apt-get source strongswan`, or the
# matching release tarball from strongswan.org on non-Debian systems) rather
# than a vendored copy. STRONGSWAN_SRC must point at a tree that has already
# been through `./configure` (needed to generate config.h) with flags
# matching the target's installed strongSwan build.
#
# Usage:
#   make STRONGSWAN_SRC=/path/to/configured/strongswan-5.9.1
#   sudo make install STRONGSWAN_SRC=/path/to/configured/strongswan-5.9.1
#
# `make test` builds and runs test/card_test.c against a throwaway instance
# of ../../../spike/akabridgetest (a fixed-test-vector Go bridge server) --
# this is what actually exercises the plugin's three response paths
# (success, sync-failure+resync, unknown identity), independent of a live
# charon/IKE session.

STRONGSWAN_SRC ?=
PLUGIN_DIR      = /usr/lib/ipsec/plugins
SONAME          = libstrongswan-eap-aka-vohive.so

CC       = gcc
CPPFLAGS = -DHAVE_CONFIG_H \
           -I. \
           -I$(STRONGSWAN_SRC) \
           -I$(STRONGSWAN_SRC)/src/libstrongswan \
           -I$(STRONGSWAN_SRC)/src/libcharon \
           -I$(STRONGSWAN_SRC)/src/libsimaka \
           -include $(STRONGSWAN_SRC)/config.h
CFLAGS   = -rdynamic -g -O2 -Wall -Wno-format -Wno-format-security -Wno-pointer-sign -fPIC -DPIC
LDFLAGS  = -shared -fPIC -DPIC -L/usr/lib/ipsec -lsimaka -lstrongswan \
           -Wl,-rpath,/usr/lib/ipsec -Wl,-soname,$(SONAME)

SOURCES = eap_aka_vohive_card.c eap_aka_vohive_plugin.c
OBJECTS = $(SOURCES:.c=.o)

.PHONY: all install clean test

all: $(SONAME)

$(SONAME): $(OBJECTS)
	@test -n "$(STRONGSWAN_SRC)" || { echo "STRONGSWAN_SRC is required"; exit 1; }
	$(CC) $(OBJECTS) $(LDFLAGS) -o $@

%.o: %.c
	@test -n "$(STRONGSWAN_SRC)" || { echo "STRONGSWAN_SRC is required"; exit 1; }
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

install: $(SONAME)
	install -m 0755 $(SONAME) $(PLUGIN_DIR)/$(SONAME)
	@echo "installed to $(PLUGIN_DIR)/$(SONAME)"
	@echo "enable it with: charon { plugins { eap-aka-vohive { load = yes } } } in a"
	@echo "fragment under /etc/strongswan.d/ (see engine/swu/charon's supervisor for why"
	@echo "it must be that directory, not an arbitrary path)"

# card_test needs its own object built with DEBUG_LEVEL=-1 to avoid pulling
# in the `charon` global that DBG1/DBG2 reference (see bus.h) -- that symbol
# only resolves when dlopen'd by the real charon process, not in a
# standalone test binary.
test: test/card_test.o
	@test -n "$(STRONGSWAN_SRC)" || { echo "STRONGSWAN_SRC is required"; exit 1; }
	$(CC) $(CPPFLAGS) $(CFLAGS) -DDEBUG_LEVEL=-1 -c eap_aka_vohive_card.c -o test/eap_aka_vohive_card_test.o
	$(CC) test/card_test.o test/eap_aka_vohive_card_test.o \
		-L/usr/lib/ipsec -lsimaka -lstrongswan -Wl,-rpath,/usr/lib/ipsec \
		-o test/card_test
	@echo "run: (cd ../../../.. && go run ./spike/akabridgetest /tmp/akabridge-test.sock &)"
	@echo "     ./test/card_test /tmp/akabridge-test.sock"

test/card_test.o: test/card_test.c
	@test -n "$(STRONGSWAN_SRC)" || { echo "STRONGSWAN_SRC is required"; exit 1; }
	$(CC) $(CPPFLAGS) $(CFLAGS) -DDEBUG_LEVEL=-1 -c $< -o $@

clean:
	rm -f $(OBJECTS) $(SONAME) test/*.o test/card_test
