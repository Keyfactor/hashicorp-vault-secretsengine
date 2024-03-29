GOARCH = amd64

UNAME = $(shell uname -s)

OS = linux

ifndef OS
	ifeq ($(UNAME), Linux)
		OS = linux
	else ifeq ($(UNAME), Darwin)
		OS = darwin
	endif
endif

.DEFAULT_GOAL := all

all: fmt build start

build:
	GOOS=$(OS) GOARCH="$(GOARCH)" go build -o vault/plugins/keyfactor cmd/keyfactor/main.go

start:
	vault server -dev -dev-root-token-id=root -dev-plugin-dir=/vault/plugins

enable:
	vault secrets enable keyfactor

clean:
	rm -f ./vault/plugins/keyfactor

fmt:
	go fmt $$(go list ./...)

.PHONY: build clean fmt start enable