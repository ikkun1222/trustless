# trustless — credential broker for AI agents
# Quality gates: gofmt + go vet + gocyclo + go test -race + secrets
.PHONY: build test vet fmt fmt-check lint complexity secrets-check audit validate-plugin check clean

build:
	go build -o trustless .

test:
	go test -v -race ./...

vet:
	go vet ./...

fmt:
	gofmt -s -w .

fmt-check:
	@test -z "$$(gofmt -s -l .)" || { echo "gofmt required on:"; gofmt -s -l .; exit 1; }
	@echo "fmt OK"

# Cyclomatic complexity gate. Pre-existing over-threshold functions are
# recorded in .gocyclo.baseline (format: "<ccn> <func> <file>") — only NEW
# violations fail the gate. Verify the baseline with:
#   go run github.com/fzipp/gocyclo/cmd/gocyclo@v0.6.0 -over 15 .
complexity:
	@go run github.com/fzipp/gocyclo/cmd/gocyclo@v0.6.0 -over 15 . 2>&1 \
		| grep -v '^exit status' | grep -v '^go: ' \
		| grep -v -f .gocyclo.baseline > /tmp/gocyclo-new.txt; \
	[ ! -s /tmp/gocyclo-new.txt ] || { echo "NEW complexity over CCN 15:"; cat /tmp/gocyclo-new.txt; exit 1; }
	@echo "complexity OK"

lint: fmt-check vet complexity

# Scan staged diff for credential patterns (git-secrets replacement, zero-dep)
# Test files are excluded: their fixture values (sk-xxx, xoxb-xxx) are dummy
# strings that would false-positive the scan (see project-conventions skill).
secrets-check:
	@git diff --cached -- . ':(exclude)*_test.go' | grep -nEi '^\+(sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|BEGIN (RSA|OPENSSH|EC) PRIVATE|xox[baprs]-[A-Za-z0-9-]{10,})' \
		&& { echo "!! SECRET PATTERN DETECTED IN STAGED DIFF"; exit 1; } || true
	@echo "secrets OK"

# Vulnerability audit (standalone — run monthly or on dependency changes)
audit:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

# Agent Plugins 1.0.0 packaging validation (plugin.json / skills)
validate-plugin:
	python3 scripts/validate-plugin.py

check: validate-plugin fmt-check vet complexity test

clean:
	rm -rf bin/
