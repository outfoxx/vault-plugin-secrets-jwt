# Install vault
FROM alpine as vault-installer
WORKDIR /vault
RUN wget https://releases.hashicorp.com/vault/1.2.3/vault_1.2.3_linux_amd64.zip -O vault.zip
RUN unzip vault.zip && chmod +x vault

# Build the addon and the test helper
FROM golang:1.13-alpine as plugin-builder
COPY main.go go.mod go.sum ${GOPATH}/src/github.com/ian-fox/vault-plugin-secrets-jwt/
COPY plugin/ ${GOPATH}/src/github.com/ian-fox/vault-plugin-secrets-jwt/plugin/
COPY test/jwtverify/jwtverify.go ${GOPATH}/src/github.com/ian-fox/vault-plugin-secrets-jwt/test/
WORKDIR ${GOPATH}/src/github.com/ian-fox/vault-plugin-secrets-jwt
RUN go build -o /vault/plugins/vault-plugin-secrets-jwt
RUN go install test/jwtverify.go

# Test environment
FROM alpine
RUN apk add bash jq
COPY --from=vault-installer /vault /usr/local/bin/
COPY test/config.hcl /vault/
COPY test/claims.json test/test.sh /test/
COPY --from=plugin-builder /vault/plugins /vault/plugins/
COPY --from=plugin-builder /go/bin/jwtverify /usr/local/bin/

WORKDIR /test
RUN chmod +x /test/test.sh
RUN /test/test.sh
