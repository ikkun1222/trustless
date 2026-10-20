package oauth

import (
	"context"
	"testing"
	"time"

	"github.com/ikkun1222/trustless/internal/backend"
)

// reloadBackend is a minimal backend that records Reload calls.
type reloadBackend struct{ reloads int }

func (b *reloadBackend) Resolve(context.Context, string) (string, error) { return "", nil }
func (b *reloadBackend) List(context.Context) ([]backend.Entry, error)   { return nil, nil }
func (b *reloadBackend) Set(context.Context, string, string) error       { return backend.ErrReadOnly }
func (b *reloadBackend) Values(context.Context, int) ([]string, error)   { return nil, nil }
func (b *reloadBackend) Reload(context.Context) error {
	b.reloads++
	return nil
}

// plainBackend has no Reload method: the decorator must still satisfy serve's
// interface assertion and clear its own cache.
type plainBackend struct{}

func (plainBackend) Resolve(context.Context, string) (string, error) { return "", nil }
func (plainBackend) List(context.Context) ([]backend.Entry, error)   { return nil, nil }
func (plainBackend) Set(context.Context, string, string) error       { return backend.ErrReadOnly }
func (plainBackend) Values(context.Context, int) ([]string, error)   { return nil, nil }

// TestOAuthBackendReloadIsVisibleAndForwards pins the regression: serve reloads
// through an interface assertion, so the decorator must expose Reload or SIGHUP
// silently does nothing.
func TestOAuthBackendReloadIsVisibleAndForwards(t *testing.T) {
	inner := &reloadBackend{}
	be := NewBackend(inner, map[string]Provider{})

	r, ok := be.(interface{ Reload(context.Context) error })
	if !ok {
		t.Fatalf("decorated backend does not satisfy serve's Reload assertion")
	}

	ob := be.(*OAuthBackend)
	ob.putCache("some/key", OAuthEntry{Access: "cached-token", ExpiresAt: time.Now().Add(time.Hour)})
	if got, hit := ob.cachedAccess("some/key", OAuthEntry{Access: "cached-token", ExpiresAt: time.Now().Add(time.Hour)}); !hit {
		t.Fatalf("precondition failed: cache not populated (got %q)", got)
	}

	if err := r.Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if inner.reloads != 1 {
		t.Fatalf("inner Reload called %d times, want 1", inner.reloads)
	}
	if _, hit := ob.cachedAccess("some/key", OAuthEntry{Access: "cached-token", ExpiresAt: time.Now().Add(time.Hour)}); hit {
		t.Fatalf("access-token cache was not cleared by Reload")
	}
}

func TestOAuthBackendReloadWithoutInnerReload(t *testing.T) {
	be := NewBackend(plainBackend{}, map[string]Provider{})
	r, ok := be.(interface{ Reload(context.Context) error })
	if !ok {
		t.Fatalf("decorated backend does not expose Reload")
	}
	if err := r.Reload(context.Background()); err != nil {
		t.Fatalf("Reload with a non-reloadable inner backend returned an error: %v", err)
	}
}
