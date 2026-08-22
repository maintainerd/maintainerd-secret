BINARY := secretd
PKG := ./cmd/secretd

.PHONY: build run tidy fmt vet test cover check sqlc proto lint-proto staticcheck clean

build:
	go build -o bin/$(BINARY) $(PKG)

run:
	go run $(PKG)

tidy:
	go mod tidy

fmt:
	gofmt -w .

vet:
	go vet ./...

test:
	go test ./...

cover:
	go test -cover ./...

staticcheck:
	staticcheck ./...

# check is the full local gate, matching what CI enforces.
check: fmt vet staticcheck test
	@test -z "$$(gofmt -l .)" || (echo "gofmt found unformatted files:"; gofmt -l .; exit 1)

# sqlc regenerates internal/storage from migrations/*.sql + internal/storage/queries/*.sql.
# The migrations are the schema source of truth, so a column added there and a column
# the Go code believes in cannot drift apart.
sqlc:
	sqlc generate

proto:
	buf generate

lint-proto:
	buf lint

clean:
	rm -rf bin/
