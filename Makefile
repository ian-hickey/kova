.PHONY: help build test release demo

VERSION ?= $(shell git describe --tags --match "v*" --always --dirty 2>/dev/null || echo dev)
LDFLAGS  = -s -w -X github.com/ian-hickey/kova/internal/cli.Version=$(VERSION)

help: ## Show targets
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-16s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build bin/kova and bin/kova-drift-demo
	go build -ldflags "$(LDFLAGS)" -o bin/kova ./cmd/kova
	go build -ldflags "$(LDFLAGS)" -o bin/kova-drift-demo ./cmd/kova-drift-demo

cli: build

test: ## Run Go tests
	go test ./...

release: ## Cross-compile the CLI into dist/
	@mkdir -p dist
	@for target in darwin/arm64 darwin/amd64 linux/amd64 linux/arm64 windows/amd64 windows/arm64; do \
		os=$${target%/*}; arch=$${target#*/}; ext=""; [ $$os = windows ] && ext=.exe; \
		echo "  $$os/$$arch"; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o dist/kova-$$os-$$arch$$ext ./cmd/kova; \
	done

demo: build ## Reproduce the Deadbugz pattern locally and show kova catching it
	@./scripts/demo-deadbugz.sh
