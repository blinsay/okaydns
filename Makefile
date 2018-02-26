NAME := okdns
PKG := github.com/blinsay/okaydns

all: clean build fmt lint vet test

.PHONY: deps
deps:
	@echo "+ $@"
	@dep ensure

# build a binary
.PHONY: build
build: $(NAME)

.PHONY: $(NAME)
$(NAME): *.go
	@echo "+ $@"
	go build -o $(NAME) ./cmd/okdns

# make sure gofmt was run
.PHONY: fmt
fmt:
	@echo "+ $@"
	@gofmt -s -l . | grep -v .pb.go | grep -v vendor | tee /dev/stderr

# golint
.PHONY: lint
lint:
	@echo "+ $@"
	@golint ./... | grep -v .pb.go | grep -v vendor | tee /dev/stderr

# go test
.PHONY: test
test:
	@echo "+ $@"
	@go test ./...

# go vet
.PHONY: vet
vet:
	@echo "+ $@"
	@go vet ./...

# clean up local executeables
.PHONY: .clean
clean:
	@echo "+ $@"
	$(RM) $(NAME)

# go install
.PHONY: install
install:
	@echo "+ $@"
	@go install .
