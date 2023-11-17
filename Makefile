EXTERNAL_TOOLS=\
	github.com/golangci/golangci-lint \
	github.com/elastic/go-licenser
GOFMT_FILES?=$$(find . -name '*.go')
BUILD_VERSION ?= $(shell ./bump_version.sh)

default: dev

# bootstrap the build by downloading additional tools
bootstrap:
	@for tool in  $(EXTERNAL_TOOLS) ; do \
		echo "Installing/Updating $$tool" ; \
		go get -u $$tool; \
	done

# dev creates binaries for testing Vault locally. These are put
# into ./bin/ as well as $GOPATH/bin.
dev:
	@go build -o vault-plugin-secrets-jwt cmd/vault-plugin-secrets-jwt/main.go

# Lint runs the linter. Not used in CI because linting is handled by golangci separately
lint:
	golangci-lint run -E goheader ./...

# test runs the unit tests and vets the code
test:
ifeq (${verbose},true)
	go test -v ./...
else
	go test ./...
endif

# functional runs a full end-to-end functional test in docker.
functional:
	@docker build --no-cache -f test/Dockerfile -t vault-jwt-e2e-test .

# stress runs an end-to-end stress test in docker.
stress:
	@docker build --no-cache -f test/Stress-Dockerfile -t vault-jwt-e2e-test .

# fmt formats the files according to go recommended style
fmt:
	@gofmt -w $(GOFMT_FILES)

.PHONY: default bootstrap dev lint test functional fmt tag
