CC ?= cc

# Build configuration. Use `make debug` or `make release`, or override it
# directly with `make CONFIG=debug bin`.
CONFIG ?= debug
ifeq ($(CONFIG),debug)
CONFIG_CFLAGS = -O0 -g3
else ifeq ($(CONFIG),release)
CONFIG_CFLAGS = -O2 -g
else
$(error CONFIG must be either debug or release)
endif

CFLAGS += $(CONFIG_CFLAGS) -std=c11 -Wall -Wextra -Werror

BUILD_DIR = build/$(CONFIG)

.PHONY: all debug release bin test
all: release
debug:
	$(MAKE) CONFIG=debug bin
release:
	$(MAKE) CONFIG=release bin
bin: build/horus-delegate
build/horus-delegate: $(BUILD_DIR)/horus-delegate
	ln -sf $(CONFIG)/horus-delegate $@
$(BUILD_DIR)/horus-delegate: main.c stun.c stun.h protocol.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) main.c stun.c -o $@
test: all
	python3 tests/integration.py
