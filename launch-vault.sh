#!
export VAULT_ADDR=http://vault.jdk.cms:8200
export KF_CONF_PATH=/home/jdk/keyfactor/vault-guides/secrets/engine/vault/plugins/config.json
x-terminal-emulator -e vault server -config=/home/jdk/keyfactor/config.txt -log-level=TRACE
