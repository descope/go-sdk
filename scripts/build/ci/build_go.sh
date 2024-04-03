#!/usr/bin/env bash

echo 'Building main package..'
go mod tidy && go mod vendor && go build -v ./...
if [ $? -ne 0 ]; then
    exit 1
fi
echo 'Building gin package..'
(cd descope/gin && go mod tidy && go mod vendor && go build)
if [ $? -ne 0 ]; then
    exit 1
fi
echo 'Building mux web app example..'
(cd examples/webapp && go mod tidy && go mod vendor && go build)
if [ $? -ne 0 ]; then
    exit 1
fi
echo 'Building gin web app example..'
(cd examples/ginwebapp && go mod tidy && go mod vendor && go build)
if [ $? -ne 0 ]; then
    exit 1
fi
echo 'Building importusers example..'
(cd examples/importusers && go mod tidy && go mod vendor && go build)
if [ $? -ne 0 ]; then
    exit 1
fi
