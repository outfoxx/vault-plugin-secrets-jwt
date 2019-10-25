EXTERNAL_TOOLS=\
	github.com/golangci/golangci-lint
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
	@go build

# Lint runs the linter. Not used in CI because linting is handled by golangci separately
lint:
	golangci-lint run ./...

# test runs the unit tests and vets the code
test:
ifeq (${verbose},true)
	go test -v ./...
else
	go test ./...
endif

# functional runs a full end-to-end functional test in docker.
functional:
	@docker build -f test/Dockerfile -t vault-jwt-e2e-test .

# fmt formats the files according to go recommended style
fmt:
	@gofmt -w $(GOFMT_FILES)

tag:
ifeq (${TRAVIS_BRANCH},master)
	@git config --global user.email "builds@travis-ci.com"
	@git config --global user.name "Travis CI"
	@git tag ${BUILD_VERSION} 
	@git push https://${GH_TOKEN}@github.com/ian-fox/vault-plugin-secrets-jwt.git ${BUILD_VERSION} > /dev/null 2>&1 
endif

.PHONY: default bootstrap dev lint test functional fmt tag
