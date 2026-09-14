.PHONY: build run test static security frontend

build:
	docker compose build

run:
	docker compose up -d

frontend:
	cd frontend && npm ci --no-audit --no-fund
	cd frontend && npm run check
	cd frontend && npm run build

test:
	cd backend && go test -mod=readonly ./...
	cd backend && go test -mod=readonly -race ./...
	cd backend && go vet -mod=readonly ./...
	$(MAKE) frontend

security:
	cd backend && GOFLAGS=-mod=readonly govulncheck ./...

static:
	@files="$$(gofmt -l backend)"; test -z "$$files" || { echo "gofmt required:"; echo "$$files"; exit 1; }
	node --check frontend/src/main.js
	node --check frontend/src/qr.js
