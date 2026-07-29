package setup

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

func SetupGPG(ctx context.Context) (string, error) {
	keyID, err := FindGPGKey(ctx)
	if err == nil && keyID != "" {
		return keyID, nil
	}
	return CreateGPGKey(ctx)
}

func FindGPGKey(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "gpg", "--list-secret-keys", "--keyid-format=long")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("gpg not available: %w", err)
	}

	for _, line := range strings.Split(stdout.String(), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "sec") {
			parts := strings.Split(line, "/")
			if len(parts) >= 2 {
				fields := strings.Fields(parts[1])
				if len(fields) > 0 {
					return fields[0], nil
				}
			}
		}
	}

	return "", fmt.Errorf("no GPG secret key found")
}

func CreateGPGKey(ctx context.Context) (string, error) {
	stdin := fmt.Sprintf(`Key-Type: RSA
Key-Length: 3072
Name-Real: trustless
Name-Email: trustless@local
Expire-Date: 5y
%s
%%commit
`, "Passphrase: ''")

	cmd := exec.CommandContext(ctx, "gpg", "--batch", "--gen-key")
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("failed to create GPG key: %w\n%s", err, strings.TrimSpace(stderr.String()))
	}

	output := stdout.String() + stderr.String()
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "key ") && strings.Contains(line, "marked as ultimately trusted") {
			idx := strings.Index(line, "key ")
			if idx >= 0 {
				fields := strings.Fields(line[idx+4:])
				if len(fields) > 0 {
					return fields[0], nil
				}
			}
		}
	}

	return "", fmt.Errorf("could not determine new GPG key ID from output:\n%s", strings.TrimSpace(output))
}
