WASM_MAIN_FILES := $(shell find plugins/wasm -type f -name main.go)
WASM_DIRS := $(patsubst %/main.go,%,$(WASM_MAIN_FILES))

.PHONY: all $(WASM_DIRS)

all: $(WASM_DIRS)

ifneq ($(strip $(WASM_DIRS)),)
$(WASM_DIRS):
	cd "$@" && env GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared -o "$(notdir $@).wasm" main.go
endif
