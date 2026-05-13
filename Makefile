BIN=bin/dns-resolver
GOCACHE=$(CURDIR)/.gocache
GOMODCACHE=$(CURDIR)/.gomodcache
FRONTEND_DIR=frontend

.PHONY: dev build test test-race fuzz bench lint docker k8s-apply run

dev:
	cd $(FRONTEND_DIR) && npm ci && npm run build
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go run ./cmd/server

build:
	cd $(FRONTEND_DIR) && npm ci && npm run build
	mkdir -p bin
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go build -ldflags="-s -w" -o $(BIN) ./cmd/server

test:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go test ./...
	cd $(FRONTEND_DIR) && npm ci && npm run check

test-race:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go test -race ./...

fuzz:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go test -fuzz=FuzzDecode -fuzztime=30s ./internal/protocol/

bench:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go test -bench=. -benchmem ./internal/protocol ./internal/cache ./internal/resolver

lint:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go vet ./...
	cd $(FRONTEND_DIR) && npm ci && npm run check && npm run lint

docker:
	docker build -t dns-resolver:latest .

k8s-apply:
	kubectl apply -f deploy/kubernetes/

run:
	./$(BIN)
