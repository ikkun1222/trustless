package backend

import (
	"context"
	"fmt"
	"os"
	"strings"
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

// Values returns the values of all environment variables with len >= minLen,
// deduplicated and sorted. For the env backend the "known secrets" are simply
// the environment variable values.
func (e *EnvBackend) Values(ctx context.Context, minLen int) ([]string, error) {
	values := make([]string, 0, len(os.Environ()))
	for _, kv := range os.Environ() {
		_, v, _ := strings.Cut(kv, "=")
		if len(v) >= minLen {
			values = append(values, v)
		}
	}
	return dedupSort(values), nil
}

// Set is not supported for the env backend: environment variables cannot be
// persisted by the broker.
func (e *EnvBackend) Set(ctx context.Context, key, value string) error {
	return fmt.Errorf("%w: env backend cannot store credentials", ErrReadOnly)
}
