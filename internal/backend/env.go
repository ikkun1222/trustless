package backend

import (
	"context"
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
