BINARY := secretd
PKG := ./cmd/secretd

.PHONY: build run tidy vet test proto lint-proto clean

build:
	go build -o bin/$(BINARY) $(PKG)

run:
	go run $(PKG)

tidy:
	go mod tidy

vet:
	go vet ./...

test:
	go test ./...

proto:
	buf generate

lint-proto:
	buf lint

clean:
	rm -rf bin/
