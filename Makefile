CARGO ?= cargo
TARGET_DIR ?= target
INSTALL_LABEL ?= com.alecuba16.rust-vmnet-proxy
INSTALL_PLIST := $(HOME)/Library/LaunchAgents/$(INSTALL_LABEL).plist
INSTALL_BIN ?= $(HOME)/.local/bin/rust-vmnet-proxy
INSTALL_LOG_DIR := $(HOME)/Library/Logs/rust-vmnet-proxy

.PHONY: build check fmt test clean install-mac update-mac start-mac stop-mac restart-mac uninstall-mac

build:
	$(CARGO) build --release --target-dir $(TARGET_DIR)

check:
	$(CARGO) check --target-dir $(TARGET_DIR)

fmt:
	$(CARGO) fmt

test:
	$(CARGO) test --target-dir $(TARGET_DIR)

clean:
	$(CARGO) clean --target-dir $(TARGET_DIR)

install-mac: build
	# The binary's own installer owns the stop-first in-place copy, adhoc
	# codesign, plist write, and kickstart (or brew services delegation).
	$(TARGET_DIR)/release/rust-vmnet-proxy install-mac

update-mac: build
	$(TARGET_DIR)/release/rust-vmnet-proxy update-mac
	@echo "Updated binary at $(INSTALL_BIN)"

start-mac:
	@if [ ! -f "$(INSTALL_PLIST)" ]; then echo "LaunchAgent plist not found at $(INSTALL_PLIST), run install-mac first" >&2; exit 1; fi
	launchctl kickstart -k "gui/$$(id -u)/$(INSTALL_LABEL)" >/dev/null 2>&1 || \
		{ launchctl bootstrap "gui/$$(id -u)" "$(INSTALL_PLIST)" && launchctl kickstart -k "gui/$$(id -u)/$(INSTALL_LABEL)"; }
	@echo "Started $(INSTALL_LABEL)"

stop-mac:
	launchctl bootout "gui/$$(id -u)/$(INSTALL_LABEL)" >/dev/null 2>&1 || true
	@echo "Stopped $(INSTALL_LABEL)"

restart-mac:
	$(MAKE) stop-mac
	@sleep 1
	$(MAKE) start-mac
	@echo "Restarted $(INSTALL_LABEL)"

uninstall-mac:
	launchctl bootout "gui/$$(id -u)/$(INSTALL_LABEL)" >/dev/null 2>&1 || true
	rm -f "$(INSTALL_PLIST)" "$(INSTALL_BIN)"
	@echo "Uninstalled $(INSTALL_LABEL); config and logs are kept"