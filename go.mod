module github.com/ian-fox/vault-plugin-secrets-jwt

go 1.13

require (
	github.com/go-test/deep v1.0.2-0.20181118220953-042da051cf31
	github.com/google/uuid v1.1.1
	github.com/hashicorp/errwrap v1.0.0
	github.com/hashicorp/go-cleanhttp v0.5.1
	github.com/hashicorp/go-hclog v0.8.0
	github.com/hashicorp/vault-plugin-auth-gcp v0.5.1
	github.com/hashicorp/vault-plugin-secrets-gcp v0.5.2
	github.com/hashicorp/vault/api v1.0.1
	github.com/hashicorp/vault/sdk v0.1.13
	golang.org/x/oauth2 v0.0.0-20190604053449-0f29369cfe45
	golang.org/x/tools v0.0.0-20191030062658-86caa796c7ab // indirect
	google.golang.org/api v0.11.0
	gopkg.in/square/go-jose.v2 v2.3.1
)
