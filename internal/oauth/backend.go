package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/ikkun1222/trustless/internal/backend"
)

const (
	// cacheSkew はキャッシュ/失効判定の安全マージン（秒）。
	// キャッシュ有効期限は expiresAt の 60 秒手前、失効判定も同じ 60 秒。
	cacheSkew = 60 * time.Second
)

// cacheEntry は OAuth access token のインメモリキャッシュ。
type cacheEntry struct {
	access    string
	expiresAt time.Time
}

// OAuthBackend は backend.Backend をラップし、OAuth エントリの
// access token を解決するデコレータ。
//
//   - OAuth エントリの値は「認証情報の入った JSON 文字列」なので、
//     Resolve が返すべきシークレットは access token そのもの。
//   - 未失効の access token はインメモリキャッシュから返し、
//     HTTP による refresh を避ける。
//   - refresh 成功時のエントリ書き戻しは CAS ガード付きで、
//     他プロセスが先に書き換えた場合は上書きしない。
type OAuthBackend struct {
	inner     backend.Backend
	providers map[string]Provider
	client    *http.Client

	mu    sync.Mutex
	cache map[string]cacheEntry
}

// NewBackend は OAuth デコレータを生成する。
// 戻り値は backend.Backend インターフェースだが、後続 Step が
// ResolveEntry / ForceRefresh を使うため *OAuthBackend への
// 型アサーションが可能な実体を返す。
func NewBackend(inner backend.Backend, providers map[string]Provider) backend.Backend {
	return &OAuthBackend{
		inner:     inner,
		providers: providers,
		client:    http.DefaultClient,
		cache:     make(map[string]cacheEntry),
	}
}

// Resolve は key のシークレットを返す。
// OAuth エントリでなければ素通しし、OAuth エントリなら access token を返す。
func (b *OAuthBackend) Resolve(ctx context.Context, key string) (string, error) {
	v, err := b.inner.Resolve(ctx, key)
	if err != nil {
		return "", err
	}
	if !IsOAuthEntry([]byte(v)) {
		return v, nil
	}
	var entry OAuthEntry
	if err := json.Unmarshal([]byte(v), &entry); err != nil {
		return "", err
	}
	provider, ok := b.providers[entry.Provider]
	if !ok {
		return "", fmt.Errorf("oauth: provider %q is not defined", entry.Provider)
	}
	if !provider.Refreshable {
		return entry.Access, nil
	}
	if cached, ok := b.cachedAccess(key, entry); ok {
		return cached, nil
	}
	// 失効（またはキャッシュなし）→ 自動 refresh。
	// 失敗時は自動リトライせず、そのままエラーを返す。
	orig := entry
	did, err := RefreshIfNeeded(ctx, b.client, provider, &entry, cacheSkew)
	if err != nil {
		return "", err
	}
	if did {
		// 他プロセスが先に書き換えていない場合のみ書き戻す。
		if err := b.writeBackIfUnchanged(ctx, key, orig, entry); err != nil {
			return "", err
		}
	}
	b.putCache(key, entry)
	return entry.Access, nil
}

// ResolveEntry は key の生の OAuth エントリを返す。
// OAuth エントリでなければ nil を返す（status/refresh コマンド用）。
func (b *OAuthBackend) ResolveEntry(ctx context.Context, key string) (*OAuthEntry, error) {
	v, err := b.inner.Resolve(ctx, key)
	if err != nil {
		return nil, err
	}
	if !IsOAuthEntry([]byte(v)) {
		return nil, nil
	}
	var entry OAuthEntry
	if err := json.Unmarshal([]byte(v), &entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

// ForceRefresh はキャッシュを無視して refresh を実行し、CAS 書き戻しまで行う。
// trustless oauth refresh コマンド用。
func (b *OAuthBackend) ForceRefresh(ctx context.Context, key string) (*OAuthEntry, error) {
	entry, err := b.ResolveEntry(ctx, key)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	provider, ok := b.providers[entry.Provider]
	if !ok {
		return nil, fmt.Errorf("oauth: provider %q is not defined", entry.Provider)
	}
	if !provider.Refreshable {
		return entry, nil
	}
	orig := *entry
	if err := Refresh(ctx, b.client, provider, entry); err != nil {
		return nil, err
	}
	if err := b.writeBackIfUnchanged(ctx, key, orig, *entry); err != nil {
		return nil, err
	}
	b.putCache(key, *entry)
	return entry, nil
}

// List は inner に素通しする。
func (b *OAuthBackend) List(ctx context.Context) ([]backend.Entry, error) {
	return b.inner.List(ctx)
}

// Set は inner に素通しする。
func (b *OAuthBackend) Set(ctx context.Context, key, value string) error {
	// 書き換え後はキャッシュが古くなるため破棄する。
	b.mu.Lock()
	delete(b.cache, key)
	b.mu.Unlock()
	return b.inner.Set(ctx, key, value)
}

// Values は各キーを OAuth 処理込みで解決した値を返す。
// OAuth キーは fresh access token が入る。dedup + 昇順ソートは既存セマンティクス。
func (b *OAuthBackend) Values(ctx context.Context, minLen int) ([]string, error) {
	entries, err := b.inner.List(ctx)
	if err != nil {
		return nil, err
	}
	values := make([]string, 0, len(entries))
	for _, e := range entries {
		v, err := b.Resolve(ctx, e.Key)
		if err != nil {
			return nil, err
		}
		if len(v) >= minLen {
			values = append(values, v)
		}
	}
	sort.Strings(values)
	return dedupSorted(values), nil
}

// cachedAccess はキャッシュが有効なら access token を返す。
// 有効期限は expiresAt の 60 秒手前（cacheSkew）で切れる。
func (b *OAuthBackend) cachedAccess(key string, entry OAuthEntry) (string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	c, ok := b.cache[key]
	if !ok {
		return "", false
	}
	// エントリに明示的な失効時刻が無い場合はキャッシュを使わない。
	if c.expiresAt.IsZero() {
		return "", false
	}
	if !time.Now().Before(c.expiresAt.Add(-cacheSkew)) {
		delete(b.cache, key)
		return "", false
	}
	return c.access, true
}

// putCache はキャッシュを更新する。
func (b *OAuthBackend) putCache(key string, entry OAuthEntry) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.cache[key] = cacheEntry{access: entry.Access, expiresAt: entry.ExpiresAt}
}

// writeBackIfUnchanged は CAS ガード付きでエントリを書き戻す。
// 現在値が refresh 実行前に読んだ値と一致する場合のみ書き戻し、
// 不一致（別プロセスが先に書いた）なら何もしない。
// 書き戻しは最良努力（best-effort）で、失敗しても呼び出し元の
// キャッシュ・返却値には影響させない。
func (b *OAuthBackend) writeBackIfUnchanged(ctx context.Context, key string, orig, updated OAuthEntry) error {
	cur, err := b.inner.Resolve(ctx, key)
	if err != nil {
		return nil // 読み直し失敗時は書き戻しを諦める
	}
	if IsOAuthEntry([]byte(cur)) {
		var curEntry OAuthEntry
		if err := json.Unmarshal([]byte(cur), &curEntry); err == nil && !sameOAuthEntry(&curEntry, &orig) {
			return nil // 別プロセスが先に書き換えた
		}
	} else {
		return nil // もう OAuth エントリではない
	}
	updatedJSON, err := json.Marshal(&updated)
	if err != nil {
		return err
	}
	return b.inner.Set(ctx, key, string(updatedJSON))
}

// sameOAuthEntry は CAS 比較用に、refresh 実行前後の refresh token が
// 一致するかを判定する。
func sameOAuthEntry(a, b *OAuthEntry) bool {
	return a.Refresh == b.Refresh
}

// dedupSorted は昇順ソート済みのスライスから重複を除く。
func dedupSorted(values []string) []string {
	out := values[:0]
	for _, v := range values {
		if len(out) == 0 || out[len(out)-1] != v {
			out = append(out, v)
		}
	}
	return out
}
