# Build the addon
FROM golang:1.17-alpine as plugin-builder
COPY main.go go.mod go.sum ${GOPATH}/src/github.com/outfoxx/vault-plugin-secrets-jwt/
COPY plugin ${GOPATH}/src/github.com/outfoxx/vault-plugin-secrets-jwt/plugin/
WORKDIR ${GOPATH}/src/github.com/outfoxx/vault-plugin-secrets-jwt
RUN go build -o /vault/plugins/vault-plugin-secrets-jwt main.go

# Package Vault
FROM vault:1.8.5
COPY --from=plugin-builder /vault/plugins /vault/plugins/
CMD ["server", "-dev", "-dev-plugin-dir=/vault/plugins"]
