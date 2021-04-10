GOFILES := $(shell find . -name "*.go")

.PHONY: tidy
tidy:
	go mod tidy

.PHONY: fmt
fmt:
	gofmt -s -w $(GOFILES)

.PHONY: lint
lint:
	golangci-lint run ./... --timeout 5m0s --exclude-use-default --exclude ".*bad syntax.*" --exclude ".*has arg itemID of wrong type string.*" --exclude "svc.Run.*is not checked.*"

.PHONY: test
test:
	go test ./...

.PHONY: check
check: tidy fmt lint test
