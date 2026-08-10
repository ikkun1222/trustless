package backend

import (
	"context"
	"errors"
	"testing"
)

func TestEnvBackendSetは読み取り専用エラーを返す(t *testing.T) {
	be := NewEnvBackend()
	err := be.Set(context.Background(), "iria/api/test-key", "secret-value")
	if !errors.Is(err, ErrReadOnly) {
		t.Fatalf("Set err = %v, want ErrReadOnly", err)
	}
}
