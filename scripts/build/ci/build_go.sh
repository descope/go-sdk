#!/usr/bin/env bash

go build -v ./...
(cd descope/gin && go build)
(cd examples/webap && go build)
(cd examples/ginwebapp && go build)