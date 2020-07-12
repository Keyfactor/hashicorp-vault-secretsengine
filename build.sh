#!
/usr/local/go/bin/go build -o vault/plugins/keyfactor cmd/mock/main.go
vault secrets disable keyfactor
vault write sys/plugins/catalog/keyfactor sha256="$(sha256sum vault/plugins/keyfactor | cut -c1-64)" command="keyfactor"
vault secrets enable keyfactor
