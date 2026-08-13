package backend

import (
	"context"
	"errors"
	"fmt"
	"sort"
)

// Entry represents a single credential entry from the backend.
type Entry struct {
	Key   string `json:"key"`
	Value string `json:"value,omitempty"`
}

// ErrNotFound is returned when a credential key is not found in the backend.
type ErrNotFound struct {
	Key    string
	Reason string
}

func (e *ErrNotFound) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("credential %q not found: %s", e.Key, e.Reason)
	}
	return fmt.Sprintf("credential %q not found", e.Key)
}

// ErrReadOnly is returned when a backend does not support writes (env).
var ErrReadOnly = errors.New("backend is read-only")

// Backend is the interface for credential storage backends.
// Implementations must be safe for concurrent use.
type Backend interface {
	// Resolve retrieves the secret value for the given key.
	Resolve(ctx context.Context, key string) (string, error)

	// List returns all available credential keys.
	List(ctx context.Context) ([]Entry, error)

	// Set stores (creates or replaces) the secret value for the given key.
	// Backends that cannot persist (e.g. env) return ErrReadOnly.
	Set(ctx context.Context, key, value string) error

	// Values returns all known secret values with len(value) >= minLen,
	// deduplicated and sorted (deterministic order for logs). Used by the
	// DLP scrubber to enumerate every known secret. Errors are fail-closed.
	Values(ctx context.Context, minLen int) ([]string, error)
}

// collectValues gathers the map values with len >= minLen, deduplicated and
// sorted (deterministic order for logs).
func collectValues(m map[string]string, minLen int) []string {
	values := make([]string, 0, len(m))
	for _, v := range m {
		if len(v) >= minLen {
			values = append(values, v)
		}
	}
	return dedupSort(values)
}

// dedupSort removes duplicate values and sorts them ascending.
func dedupSort(values []string) []string {
	sort.Strings(values)
	out := values[:0]
	for _, v := range values {
		if len(out) == 0 || out[len(out)-1] != v {
			out = append(out, v)
		}
	}
	return out
}
