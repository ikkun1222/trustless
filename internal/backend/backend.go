package backend

import (
	"context"
	"fmt"
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

// Backend is the interface for credential storage backends.
// Implementations must be safe for concurrent use.
type Backend interface {
	// Resolve retrieves the secret value for the given key.
	Resolve(ctx context.Context, key string) (string, error)

	// List returns all available credential keys.
	List(ctx context.Context) ([]Entry, error)
}
