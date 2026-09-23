.PHONY: run build test css
run:
	go run ./cmd/juardrails
build:
	go build -trimpath -o bin/juardrails ./cmd/juardrails
	go build -trimpath -o bin/juard ./cmd/juard
test:
	go test -race ./...
css:
	npm ci
	npm run build:vendor
	npm run build:css
