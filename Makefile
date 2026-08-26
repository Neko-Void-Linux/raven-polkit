CC ?= gcc
PREFIX ?= /usr
LIBDIR ?= $(PREFIX)/lib/raven-polkit
PROMPT_PATH ?= $(LIBDIR)/raven-polkit-prompt

CFLAGS ?= -Os -fdata-sections -ffunction-sections -Wall -Wextra -Wno-unused-parameter
CFLAGS += -DPROMPT_DEFAULT_PATH="\"$(PROMPT_PATH)\""
LDFLAGS ?= -Os -s -Wl,--gc-sections -Wl,--as-needed

all: raven-polkit-agent raven-polkit-prompt size

raven-polkit-agent: raven-polkit-agent.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< \
		$(shell pkg-config --cflags --libs dbus-1)
	strip --strip-unneeded $@ 2>/dev/null || true

raven-polkit-prompt: raven-polkit-prompt.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< \
		$(shell pkg-config --cflags --libs gtk+-3.0)
	strip --strip-unneeded $@ 2>/dev/null || true

size: raven-polkit-agent raven-polkit-prompt
	@echo "=== Binary sizes ==="
	@ls -lh raven-polkit-agent raven-polkit-prompt
	@echo "=== Daemon linked libraries (no GTK!) ==="
	@ldd raven-polkit-agent | awk '{print $$1}' | grep -v '^$$' | sort
	@echo ""
	@echo "To test: make run"
	@echo "To run the prompt manually: ./raven-polkit-prompt --message 'Test' --user $$(whoami)"

install: all
	install -d $(DESTDIR)$(LIBDIR)
	install -m 755 raven-polkit-agent $(DESTDIR)$(LIBDIR)/
	install -m 755 raven-polkit-prompt $(DESTDIR)$(LIBDIR)/

run: all
	@echo "Starting raven-polkit-agent (Ctrl+C to stop)..."
	@./raven-polkit-agent

release:
	@./build-release.sh

clean:
	rm -f raven-polkit-agent raven-polkit-prompt

.PHONY: all size install clean run release
