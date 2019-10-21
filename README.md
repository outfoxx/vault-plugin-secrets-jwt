# Vault Plugin: JWT Backend

This is a standalone backend plugin for use with [Hashicorp Vault](https://www.github.com/hashicorp/vault).
This plugin provides the ability to sign [JSON Web Tokens](https://jwt.io) (JWTs) without ever having the signing keys leave Vault.

It is still under early development and should not be used anywhere.

**Please note**: Hashicorp take Vault's security and their users' trust very seriously. If you believe you have found a security issue in Vault, _please responsibly disclose_ by contacting them at [security@hashicorp.com](mailto:security@hashicorp.com).

## Quick Links
    - Vault Website: https://www.vaultproject.io
    - Main Project Github: https://www.github.com/hashicorp/vault
    - Package docs: https://godoc.org/github.com/ian-fox/vault-plugin-secrets-jwt
    - JWT docs: https://jwt.io

## TODO
* Interact with other backends, like the PKI secrets backend
* Better docs, help messages
* Does vault convert to string automatically? Investigate.
* Create and expire keys on ticker instead of lazily(?)
* Maybe use a linked list or something instead of a slice
* Automatically assign claims like expiry 
* Generate signing keys on the fly for different-length leases
* Integration test
* CD Pipeline