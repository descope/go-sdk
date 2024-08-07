# HELP
# This will output the help for each task
.PHONY: help build run

help: ## This help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help

build: ## Build package
	go mod tidy && go build ./...
run-example: ## Run example web application
	cd examples/webapp && go mod tidy && go run main.go
run-gin-example: ## Run example web application
	cd examples/ginwebapp && go mod tidy && go run main.go
