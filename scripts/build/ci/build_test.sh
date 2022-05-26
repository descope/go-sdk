#!/usr/bin/env bash

go test -v -coverpkg=./... -race -coverprofile=raw_coverage.out -covermode=atomic ./...
if [ $? -ne 0 ]; then
    exit 1
fi

cat raw_coverage.out | grep -v -e ".*\/.*mock.*\/.*\.go\:.*" | grep -v -e ".*mock.go\:.*" | grep -v -e "${1:-"empty"}" > coverage.out

go install github.com/dave/courtney@master
courtney -l coverage.out 
go tool cover -func coverage.out | grep total | awk '{print $3}'
go tool cover -html=coverage.out -o coverage.html
