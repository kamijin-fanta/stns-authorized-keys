GO ?= go
GOLINES_VERSION ?= v0.15.0
BUILD_OUTPUT ?= stns-authorized-keys

.PHONY: format test test-race vet build check

build:
	$(GO) build -trimpath -o $(BUILD_OUTPUT) .

format:
	gofmt -w .
	$(GO) run github.com/golangci/golines@$(GOLINES_VERSION) -w .

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

check: test test-race vet build
