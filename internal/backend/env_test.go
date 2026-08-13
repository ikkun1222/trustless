package backend

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestEnvBackendSetは読み取り専用エラーを返す(t *testing.T) {
	be := NewEnvBackend()
	err := be.Set(context.Background(), "iria/api/test-key", "secret-value")
	if !errors.Is(err, ErrReadOnly) {
		t.Fatalf("Set err = %v, want ErrReadOnly", err)
	}
}

func TestValuesは環境変数の値のうちminLen以上のものを返す(t *testing.T) {
	t.Setenv("TRUSTLESS_SHORT", "abc")
	t.Setenv("TRUSTLESS_API_KEY", "sk-or-v1-secret-value")
	t.Setenv("TRUSTLESS_EMPTY", "")

	be := NewEnvBackend()
	got, err := be.Values(context.Background(), 8)
	if err != nil {
		t.Fatalf("values: %v", err)
	}

	// テスト環境の他の環境変数（PATH 等）に依存しないよう、
	// TRUSTLESS_ プレフィックスのものだけ検証する
	var mine []string
	for _, v := range got {
		if strings.HasPrefix(v, "sk-or-v1-secret-value") {
			mine = append(mine, v)
		}
	}
	want := []string{"sk-or-v1-secret-value"}
	if !slices.Equal(mine, want) {
		t.Fatalf("values = %q, want %q (TRUSTLESS_ only)", mine, want)
	}
	if !slices.Contains(got, "sk-or-v1-secret-value") {
		t.Fatalf("values missing API key: %q", got)
	}
	if slices.Contains(got, "abc") {
		t.Fatalf("values contains %q shorter than minLen 8", "abc")
	}
	if slices.Contains(got, "") {
		t.Fatalf("values contains empty string")
	}
}
