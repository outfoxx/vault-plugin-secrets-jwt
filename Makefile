EXTERNAL_TOOLS=\
	github.com/golangci/golangci-lint
GOFMT_FILES?=$$(find . -name '*.go')

default: dev

# dev creates binaries for testing Vault locally. These are put
# into ./bin/ as well as $GOPATH/bin.
dev:
	@go build

# test runs the unit tests and vets the code
test:
	golangci-lint run ./...
	go test ./...

# bootstrap the build by downloading additional tools
bootstrap:
	@for tool in  $(EXTERNAL_TOOLS) ; do \
		echo "Installing/Updating $$tool" ; \
		go get -u $$tool; \
	done

fmt:
	gofmt -w $(GOFMT_FILES)


.PHONY: default test vet bootstrap fmt
