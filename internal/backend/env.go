package backend

import (
	"context"
	"fmt"
	"os"
)

type EnvBackend struct{}

func NewEnvBackend() *EnvBackend {
	return &EnvBackend{}
}

func (e *EnvBackend) Resolve(ctx context.Context, key string) (string, error) {
	val := os.Getenv(key)
	if val == "" {
		return "", &ErrNotFound{Key: key, Reason: "environment variable not set or empty"}
	}
	return val, nil
}

func (e *EnvBackend) List(ctx context.Context) ([]Entry, error) {
	return []Entry{}, nil
}

// Set is not supported for the env backend: environment variables cannot be
// persisted by the broker.
func (e *EnvBackend) Set(ctx context.Context, key, value string) error {
	return fmt.Errorf("%w: env backend cannot store credentials", ErrReadOnly)
}
