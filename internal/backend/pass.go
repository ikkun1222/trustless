package backend

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// PassBackend implements Backend using the `pass` CLI.
type PassBackend struct{}

func NewPassBackend() *PassBackend {
	return &PassBackend{}
}

// Resolve retrieves a secret from pass.
func (p *PassBackend) Resolve(ctx context.Context, key string) (string, error) {
	cmd := exec.CommandContext(ctx, "pass", "show", key)
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			stderr := strings.TrimSpace(string(exitErr.Stderr))
			return "", &ErrNotFound{Key: key, Reason: stderr}
		}
		return "", fmt.Errorf("pass show %s: %w", key, err)
	}

	// First line is the password/secret
	val := strings.SplitN(string(out), "\n", 2)[0]
	return strings.TrimRight(val, "\r\n"), nil
}

// List returns all entries in the pass store by scanning the filesystem directly.
// This is more reliable than parsing `pass ls` tree output.
func (p *PassBackend) List(ctx context.Context) ([]Entry, error) {
	storeDir := passStoreDir()
	if _, err := os.Stat(storeDir); os.IsNotExist(err) {
		return nil, fmt.Errorf("pass store not found at %s", storeDir)
	}

	var entries []Entry
	err := filepath.WalkDir(storeDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// Skip directory entries and non-.gpg files
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".gpg") {
			return nil
		}

		// Convert filesystem path to pass key
		rel, err := filepath.Rel(storeDir, path)
		if err != nil {
			return nil
		}

		// Remove .gpg extension
		key := strings.TrimSuffix(rel, ".gpg")
		entries = append(entries, Entry{Key: key})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("scan pass store: %w", err)
	}

	return entries, nil
}

// Values decrypts every entry in the pass store via Resolve and returns the
// secret values with len(value) >= minLen, deduplicated and sorted. A single
// decryption failure fails closed: callers must not scrub with a partial list.
func (p *PassBackend) Values(ctx context.Context, minLen int) ([]string, error) {
	entries, err := p.List(ctx)
	if err != nil {
		return nil, err
	}
	values := make([]string, 0, len(entries))
	for _, e := range entries {
		val, err := p.Resolve(ctx, e.Key)
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", e.Key, err)
		}
		if len(val) >= minLen {
			values = append(values, val)
		}
	}
	return dedupSort(values), nil
}

// Set stores a secret in pass, replacing any existing value. The value is fed
// via stdin so it never appears on argv (ps / shell history leak).
func (p *PassBackend) Set(ctx context.Context, key, value string) error {
	cmd := exec.CommandContext(ctx, "pass", "insert", "--force", key)
	cmd.Stdin = strings.NewReader(value + "\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("pass insert %s: %w: %s", key, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// passStoreDir returns the pass password store directory.
func passStoreDir() string {
	if d := os.Getenv("PASSWORD_STORE_DIR"); d != "" {
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join("/home", ".password-store")
	}
	return filepath.Join(home, ".password-store")
}
