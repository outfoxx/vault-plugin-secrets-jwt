#!/bin/bash

# Configure vault
vault server -dev -dev-root-token-id="root" -config=/vault/config.hcl &
VAULT_PROC=$!

export VAULT_ADDR='http://127.0.0.1:8200'

SHASUM=$(sha256sum "/vault/plugins/vault-plugin-secrets-jwt" | cut -d " " -f1)

vault login root

vault plugin register -sha256 $SHASUM vault-plugin-secrets-jwt
vault secrets enable -path=jwt vault-plugin-secrets-jwt

# Change the expiry time
vault write jwt/config "key_ttl=2s" "jwt_ttl=3s"

# Create a token
vault write -field=token jwt/sign @claims.json > jwt1.txt

# Check that the token is as we expect
jwtverify $(cat jwt1.txt) $VAULT_ADDR/v1/jwt/jwks | tee decoded.txt
[[ $(cat decoded.txt | jq '.iss') = "Zapp Brannigan" ]]
[[ $(cat decoded.txt | jq '.exp') =~ [0-9]+ ]]

# Wait and generate a second jwt
sleep 3
vault write -field=token jwt/sign @claims.json > jwt2.txt
sleep 3

# We should be able to verify the second JWT, but not the first.
jwtverify $(cat jwt2.txt) $VAULT_ADDR/v1/jwt/jwks
if ! jwtverify $(cat jwt1.txt) $VAULT_ADDR/v1/jwt/jwks; then
    echo "Key rotated successfully."
else
    echo "Key rotation failed, first JWT still valid."
    exit 1
fi
