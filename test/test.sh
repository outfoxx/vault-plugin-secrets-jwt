#!/bin/bash

# Configure vault
vault server -dev -dev-root-token-id="root" -config=/vault/config.hcl &
VAULT_PROC=$!

export VAULT_ADDR='http://127.0.0.1:8200'

expect_equal() {
    # Usage: expect_equal op1 op2 message
    if [[ ! $1 = $2 ]]; then
        echo $3 ": " $1 "!=" $2
        exit 1
    fi
}

expect_not_equal() {
    # Usage: expect_equal op1 op2 message
    if [[ $1 = $2 ]]; then
        echo $3 ": " $1 "=" $2
        exit 1
    fi
}

expect_match() {
    # Usage: expect_match str pattern message
    if [[ ! $1 =~ $2 ]]; then
        echo $3 ": " $1 "does not match" $2
        exit 1
    fi
}

expect_no_match() {
    # Usage: expect_no_match str pattern message
    if [[ $1 =~ $2 ]]; then
        echo $3 ": " $1 "matches" $2
        exit 1
    fi
}

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
expect_equal "$(cat decoded.txt | jq '.sub')" '"Zapp Brannigan"' "Wrong subject"
expect_match $(cat decoded.txt | jq '.exp') "[0-9]+" "Invalid 'exp' claim"
expect_match $(cat decoded.txt | jq '.iat') "[0-9]+" "Invalid 'iat' claim"

EXP_TIME=$(cat decoded.txt | jq '.exp')
IAT_TIME=$(cat decoded.txt | jq '.iat')
if [[ "(( EXP_TIME - IAT_TIME ))" -ne 3 ]]; then
    echo "times don't match"
    exit 1
fi

# Wait and generate a second jwt
sleep 3
vault write jwt/config "set_iat=false"
vault write -field=token jwt/sign @claims.json > jwt2.txt
sleep 3

# We should be able to verify the second JWT, but not the first.
jwtverify $(cat jwt2.txt) $VAULT_ADDR/v1/jwt/jwks | tee decoded2.txt
if ! jwtverify $(cat jwt1.txt) $VAULT_ADDR/v1/jwt/jwks; then
    echo "Key rotated successfully."
else
    echo "Key rotation failed, first JWT still valid."
    exit 1
fi

# Second key should not have an iat claim
expect_no_match "$(cat decoded2.txt)" "iat" "should not have 'iat' claim"

# Keys should have different UUIDs.
expect_not_equal $(cat decoded.txt | jq '.jti') $(cat decoded2.txt | jq '.jti') "JTI claims should differ"
