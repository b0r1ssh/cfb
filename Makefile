.DEFAULT_GOAL = help

SHELL := /bin/bash

GOLANGCI_LINT_VERSION := v$(shell cat .golangci-lint-version)


.PHONY: lint
lint:  ## Run linter
	@go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run --config=./.golangci.yaml --verbose --timeout 5m

.PHONY: lint-fix
lint-fix:  ## Run linter and automatically fix issues
	@go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run --config=./.golangci.yaml --verbose --timeout 5m --fix


.PHONY: tests
tests:  ## Run tests
	@go test -v -cover -coverprofile=coverage.out ./...

.PHONY: help
help:
	@ grep -h -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
