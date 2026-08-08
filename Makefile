CC      := gcc
CFLAGS  := -Os -s -fdata-sections -ffunction-sections -Wl,--gc-sections \
           -Wall -Wextra -Wno-unused-parameter
LDFLAGS := -Os -s -Wl,--gc-sections -Wl,--as-needed

all: polkit-agent polkit-prompt size

polkit-agent: polkit-agent.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< \
		$(shell pkg-config --cflags --libs dbus-1)
	strip --strip-unneeded $@ 2>/dev/null || true

polkit-prompt: polkit-prompt.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< \
		$(shell pkg-config --cflags --libs gtk+-3.0)
	strip --strip-unneeded $@ 2>/dev/null || true

size: polkit-agent polkit-prompt
	@echo "=== Binary sizes ==="
	@ls -lh polkit-agent polkit-prompt
	@echo "=== Daemon linked libraries (no GTK!) ==="
	@ldd polkit-agent | awk '{print $$1}' | grep -v '^$$' | sort
	@echo ""
	@echo "To test: make run"
	@echo "To run the prompt manually: ./polkit-prompt --message 'Test' --user $$(whoami)"

install: all
	install -d $(DESTDIR)/usr/lib/polkit-agent-lite
	install -m 755 polkit-agent $(DESTDIR)/usr/lib/polkit-agent-lite/
	install -m 755 polkit-prompt $(DESTDIR)/usr/lib/polkit-agent-lite/

run: all
	@echo "Starting polkit-agent (Ctrl+C to stop)..."
	@./polkit-agent

clean:
	rm -f polkit-agent polkit-prompt

.PHONY: all size install clean run
