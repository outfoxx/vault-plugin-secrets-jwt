#!/bin/bash

# Configure vault
vault server -dev -dev-root-token-id="root" -config=/vault/config.hcl &
VAULT_PROC=$!

export VAULT_ADDR='http://127.0.0.1:8200'

SHASUM=$(sha256sum "/vault/plugins/vault-plugin-secrets-jwt" | cut -d " " -f1)

vault login root

vault plugin register -sha256 $SHASUM vault-plugin-secrets-jwt
vault secrets enable -path=jwt vault-plugin-secrets-jwt

# Check signature
vault write -field=token jwt/sign @claims.json > jwt.txt
jwtverify $(cat jwt.txt) $VAULT_ADDR/v1/jwt/jwks | tee result.txt

# Expect the results to match
[[ $(cat result.txt) =~ "Zapp Brannigan" ]]
