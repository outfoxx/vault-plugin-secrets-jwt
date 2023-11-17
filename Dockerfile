#
# Copyright 2021 Outfox, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# Produces a Vault container that has the plugin included in the
# /vault/plugins directory. It also starts the server in dev mode
# with the `-dev-plugin-dir` set correctly.

# Build the addon
FROM golang:1.19-alpine as plugin-builder
COPY go.mod go.sum ${GOPATH}/src/github.com/outfoxx/vault-plugin-secrets-jwt/
COPY cmd/vault-plugin-secrets-jwt/main.go ${GOPATH}/src/github.com/outfoxx/vault-plugin-secrets-jwt/cmd/vault-plugin-secrets-jwt/
COPY plugin ${GOPATH}/src/github.com/outfoxx/vault-plugin-secrets-jwt/plugin/
WORKDIR ${GOPATH}/src/github.com/outfoxx/vault-plugin-secrets-jwt
RUN go build -o /vault/plugins/vault-plugin-secrets-jwt cmd/vault-plugin-secrets-jwt/main.go

# Package Vault
FROM hashicorp/vault:1.15.2
COPY --from=plugin-builder /vault/plugins /vault/plugins/
CMD ["server", "-dev", "-dev-plugin-dir=/vault/plugins"]
