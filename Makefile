BINARY = "keyfactor"
VERSION = "v1.3.1"

UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

ifeq ($(UNAME_S),Linux)
	OS = linux
else ifeq ($(UNAME_S),Darwin)
	OS = darwin
endif

ifeq ($(UNAME_M),x86_64)
	GOARCH = amd64
else ifeq ($(UNAME_M),arm64)
	GOARCH = arm64
else ifeq ($(UNAME_M),i386)
	GOARCH = 386
endif

.DEFAULT_GOAL := all

all: fmt build start

build:
	GOOS=$(OS) GOARCH=$(GOARCH) go build -o vault/plugins/keyfactor cmd/keyfactor/main.go

start:
	vault server -dev -dev-root-token-id=root -dev-plugin-dir=./vault/plugins

register:
	vault write sys/plugins/catalog/secret/keyfactor sha_256=$(shell shasum -a 256 ./vault/plugins/keyfactor | cut -d ' ' -f 1) command="keyfactor"

enable:
	export VAULT_ADDR=http://localhost:8200
	export VAULT_TOKEN=root
	vault secrets enable keyfactor

config_oauth:
	vault write keyfactor/config \
		url="https://int1230-oauth.eastus2.cloudapp.azure.com" \
		client_id="vault-secrets-engine" \
		client_secret="c6rxzs6Hz8JjlkFR87ra18WBqlhXdwMO" \
		token_url="https://int1230-oauth.eastus2.cloudapp.azure.com/oauth2/token" \
		template="SslServerProfile" \
		CA="TestDriveSub-G1"

clean:
	rm -f ./vault/plugins/keyfactor

fmt:
	go fmt $$(go list ./...)

release:
	GOOS=darwin GOARCH=amd64 go build -o ./bin/${BINARY}_${VERSION}_darwin_amd64
	GOOS=freebsd GOARCH=386 go build -o ./bin/${BINARY}_${VERSION}_freebsd_386
	GOOS=freebsd GOARCH=amd64 go build -o ./bin/${BINARY}_${VERSION}_freebsd_amd64
	GOOS=freebsd GOARCH=arm go build -o ./bin/${BINARY}_${VERSION}_freebsd_arm
	GOOS=linux GOARCH=386 go build -o ./bin/${BINARY}_${VERSION}_linux_386
	GOOS=linux GOARCH=amd64 go build -o ./bin/${BINARY}_${VERSION}_linux_amd64
	GOOS=linux GOARCH=arm go build -o ./bin/${BINARY}_${VERSION}_linux_arm
	GOOS=openbsd GOARCH=386 go build -o ./bin/${BINARY}_${VERSION}_openbsd_386
	GOOS=openbsd GOARCH=amd64 go build -o ./bin/${BINARY}_${VERSION}_openbsd_amd64
	GOOS=solaris GOARCH=amd64 go build -o ./bin/${BINARY}_${VERSION}_solaris_amd64
	GOOS=windows GOARCH=386 go build -o ./bin/${BINARY}_${VERSION}_windows_386
	GOOS=windows GOARCH=amd64 go build -o ./bin/${BINARY}_${VERSION}_windows_amd64

.PHONY: build clean fmt start enable register release