# vault-plugin-kmip

KMIP backend manages certificates and writes them to the backend.

docs: [代码设计 (yuque.com)](https://www.yuque.com/u39032422/vault/stxoi517z15f3g5c) 

passwd：fbg9

## Prerequisites

1. Target API with CRUD capabilities for secrets.
1. Golang 1.23+
1. Docker &  Docker Compose 20.10+
1. Terraform 1.0+
1. Google Cloud Platform

## Install

1. Run `go mod init`.

1. Build the secrets engine into a plugin using Go.
   ```shell
   $ go build -o vault/plugins/vault-plugin-kmip cmd/vault-plugin-kmip/main.go
   ```

1. You can find the binary in `vault/plugins/`.
   ```shell
   $ ls vault/plugins/
   ```

1. Run a Vault server in `dev` mode to register and try out the plugin.
   ```shell
   $ vault server -dev -dev-root-token-id=root -dev-plugin-dir=./vault/plugins
   ```
