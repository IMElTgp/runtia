APP := runtia
GO ?= go
SRC := ./cmd
OUT := ./bin/$(APP)
INSTALL_DIR ?= $(HOME)/.local/bin
GOCACHE ?= $(CURDIR)/.cache/go-build

.PHONY: build install run clean

build:
	mkdir -p ./bin $(GOCACHE)
	GOCACHE=$(GOCACHE) $(GO) build -ldflags="-s -w" -o $(OUT) $(SRC)

install: build
	mkdir -p $(INSTALL_DIR)
	cp $(OUT) $(INSTALL_DIR)/$(APP)
	chmod +x $(INSTALL_DIR)/$(APP)
	@printf 'installed %s\n' "$(INSTALL_DIR)/$(APP)"
	@printf 'make sure %s is in PATH to run `%s` directly\n' "$(INSTALL_DIR)" "$(APP)"

run: build
	$(OUT) $(ARGS)

clean:
	rm -f $(OUT)
