.DEFAULT_GOAL := help

.PHONY:  help clean build install test ensure-go
.SILENT: help clean build install test ensure-go

help: Makefile ## this help message
	grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

clean: ## removes build binary
	rm migrate

build: ensure-go ## builds the migrate command line tool
	go build .
	echo Run $$'\e[33m'./migrate$$'\e[0m' for usage and help

install: ensure-go ## installs the migrate command line tool to $GOPATH/bin
	go install .
	echo The $$'\e[33m'migrate$$'\e[0m' has been installed to $$GOPATH/bin

ensure-go:
	if ! command -v go &> /dev/null; then \
	    echo \\nInstall the go compiler from $$'\e[33m'https://go.dev/dl/$$'\e[0m'\\n ;\
	    false ;\
	fi
