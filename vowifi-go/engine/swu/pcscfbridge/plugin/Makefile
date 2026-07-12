# Builds libstrongswan-p-cscf-vohive.so, the C plugin bridging charon's
# P-CSCF discovery (RFC 7651 IKEv2 configuration attributes) to the Go
# pcscfbridge (see bridge.go one level up). Mirrors
# ../../akabridge/plugin/Makefile exactly -- see that file for the reasoning
# behind compiling against a configured strongSwan source tree instead of a
# vendored/-dev header package.
#
# Usage:
#   make STRONGSWAN_SRC=/path/to/configured/strongswan-5.9.1
#   sudo make install STRONGSWAN_SRC=/path/to/configured/strongswan-5.9.1

STRONGSWAN_SRC ?=
PLUGIN_DIR      = /usr/lib/ipsec/plugins
SONAME          = libstrongswan-p-cscf-vohive.so

CC       = gcc
CPPFLAGS = -DHAVE_CONFIG_H \
           -I. \
           -I$(STRONGSWAN_SRC) \
           -I$(STRONGSWAN_SRC)/src/libstrongswan \
           -I$(STRONGSWAN_SRC)/src/libcharon \
           -include $(STRONGSWAN_SRC)/config.h
CFLAGS   = -rdynamic -g -O2 -Wall -Wno-format -Wno-format-security -Wno-pointer-sign -fPIC -DPIC
LDFLAGS  = -shared -fPIC -DPIC -L/usr/lib/ipsec -lstrongswan \
           -Wl,-rpath,/usr/lib/ipsec -Wl,-soname,$(SONAME)

SOURCES = p_cscf_vohive_handler.c p_cscf_vohive_plugin.c
OBJECTS = $(SOURCES:.c=.o)

.PHONY: all install clean

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
	@echo "enable it with: charon { plugins { p-cscf-vohive { load = yes } } } in a"
	@echo "fragment under /etc/strongswan.d/ (see engine/swu/charon's supervisor for why"
	@echo "it must be that directory, not an arbitrary path)"

clean:
	rm -f $(OBJECTS) $(SONAME)
