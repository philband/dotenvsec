set shell := ["bash", "-euo", "pipefail", "-c"]

aqua_config := justfile_directory() / "aqua/aqua.yaml"
aqua := "AQUA_CONFIG=" + quote(aqua_config) + " aqua exec --"

default:
    @just --list

tools:
    AQUA_CONFIG={{quote(aqua_config)}} aqua install

tools-update:
    cd aqua && aqua up

tools-checksum:
    cd aqua && aqua upc --prune

tools-verify:
    cd aqua && aqua upc --prune
    git diff --exit-code -- aqua/aqua.yaml aqua/aqua-checksums.json

fmt:
    {{aqua}} gofmt -w cmd internal pkg

test:
    {{aqua}} go test -race ./...

lint:
    {{aqua}} go vet ./...
    {{aqua}} golangci-lint run

vuln:
    {{aqua}} govulncheck ./...

build:
    mkdir -p bin
    {{aqua}} go build -trimpath -o bin/dotenvsec ./cmd/dotenvsec
    {{aqua}} go build -trimpath -o bin/dotenvsec-provider-sops ./cmd/dotenvsec-provider-sops

cross-build:
    mkdir -p dist
    GOOS=darwin GOARCH=arm64 {{aqua}} go build -trimpath -o dist/dotenvsec-darwin-arm64 ./cmd/dotenvsec
    GOOS=darwin GOARCH=arm64 {{aqua}} go build -trimpath -o dist/dotenvsec-provider-sops-darwin-arm64 ./cmd/dotenvsec-provider-sops
    GOOS=linux GOARCH=amd64 {{aqua}} go build -trimpath -o dist/dotenvsec-linux-amd64 ./cmd/dotenvsec
    GOOS=linux GOARCH=amd64 {{aqua}} go build -trimpath -o dist/dotenvsec-provider-sops-linux-amd64 ./cmd/dotenvsec-provider-sops

checksums: cross-build
    cd dist && shasum -a 256 \
        dotenvsec-darwin-arm64 \
        dotenvsec-provider-sops-darwin-arm64 \
        dotenvsec-linux-amd64 \
        dotenvsec-provider-sops-linux-amd64 > checksums.txt

sbom: cross-build
    {{aqua}} syft dir:. -o spdx-json=dist/source.spdx.json

workflow-lint:
    {{aqua}} actionlint

verify: tools-verify fmt test lint vuln workflow-lint checksums
    ./scripts/check-plaintext.sh
    cd dist && shasum -a 256 -c checksums.txt

clean:
    rm -rf bin dist