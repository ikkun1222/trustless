package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/ikkun1222/trustless/internal/backend"
	"github.com/ikkun1222/trustless/internal/config"
)

// stdout / stderr は出力先。テストから差し替え可能にするため変数としている。
var stdout io.Writer = os.Stdout
var stderr io.Writer = os.Stderr

const (
	exitUsage = 1
	exitError = 2
)

// usage は oauth コマンドの利用法を stderr に出力する。
func usage() {
	fmt.Fprintln(stderr, "Usage: trustless oauth <command> [<args>]")
	fmt.Fprintln(stderr, "")
	fmt.Fprintln(stderr, "Commands:")
	fmt.Fprintln(stderr, "  login <provider> <key>   Device flow login; stores the OAuth entry")
	fmt.Fprintln(stderr, "  refresh <key>            Force refresh the OAuth entry")
	fmt.Fprintln(stderr, "  status <key>             Show entry status (valid/expired/reauth_required)")
	fmt.Fprintln(stderr, "  providers                List configured providers")
}

// errf はエラーメッセージを stderr に出力する。
func errf(format string, args ...any) {
	fmt.Fprintf(stderr, "Error: "+format+"\n", args...)
}

// Run は `trustless oauth` サブコマンドを実行する。
// 戻り値は exit code: usage エラーは 1、実行時エラーは 2、成功は 0。
func Run(args []string, be backend.Backend, cfg *config.Config) int {
	if len(args) < 1 {
		usage()
		return exitUsage
	}
	switch args[0] {
	case "login":
		return login(args[1:], be, cfg)
	case "refresh":
		return refresh(args[1:], be)
	case "status":
		return status(args[1:], be)
	case "providers":
		return providers(cfg)
	default:
		fmt.Fprintf(stderr, "Unknown oauth subcommand: %s\n", args[0])
		usage()
		return exitUsage
	}
}

// login は device code フロー（RFC 8628）で認証し、得られたエントリを
// backend に保存して結果を JSON で出力する。--json フラグは既定。
func login(args []string, be backend.Backend, cfg *config.Config) int {
	if len(args) < 2 {
		errf("Usage: trustless oauth login <provider> <key>")
		return exitUsage
	}
	providerName, key := args[0], args[1]
	cp, ok := cfg.OAuth.Providers[providerName]
	if !ok {
		errf("oauth: provider %q is not defined", providerName)
		return exitError
	}
	provider := toProvider(providerName, cp)
	ob, ok := be.(*OAuthBackend)
	if !ok {
		errf("oauth: backend does not support OAuth")
		return exitError
	}

	resp, err := DeviceStart(context.Background(), ob.client, provider)
	if err != nil {
		errf("%v", err)
		return exitError
	}
	// ユーザーに提示する認可 URL を stdout に表示する。
	if resp.VerificationURIComplete != "" {
		fmt.Fprintln(stdout, resp.VerificationURIComplete)
	} else if resp.VerificationURI != "" {
		fmt.Fprintln(stdout, resp.VerificationURI+"?user_code="+resp.UserCode)
	}

	data, err := DevicePoll(context.Background(), ob.client, provider, resp.DeviceCode, resp.Interval, resp.ExpiresIn)
	if err != nil {
		errf("%v", err)
		return exitError
	}
	// 最小化エントリで保存する: access / scopes / expires_at はランタイム専用
	// であり永続化しない（access は resolve 時に refresh で取得）。
	// Refreshable=false のプロバイダ（v1 では発生しない）のみ access も保存する。
	entry := &OAuthEntry{
		Provider: providerName,
		Refresh:  data.RefreshToken,
	}
	if !provider.Refreshable {
		entry.Access = data.AccessToken
	}
	if data.RefreshExpiresIn > 0 {
		entry.RefreshExpiresAt = time.Now().Add(time.Duration(data.RefreshExpiresIn) * time.Second)
	}
	// pass の 1 行制約を満たす compact 単一行 JSON で保存する。
	entryJSON, err := json.Marshal(entry)
	if err != nil {
		errf("%v", err)
		return exitError
	}
	if err := be.Set(context.Background(), key, string(entryJSON)); err != nil {
		errf("%v", err)
		return exitError
	}
	writeJSON(map[string]any{
		"key":        key,
		"provider":   providerName,
		"expires_at": formatTime(entry.ExpiresAt),
	})
	return 0
}

// refresh は ForceRefresh でエントリの access token を更新する。
// access token は出力しない。
func refresh(args []string, be backend.Backend) int {
	if len(args) < 1 {
		errf("Usage: trustless oauth refresh <key>")
		return exitUsage
	}
	key := args[0]
	ob, ok := be.(*OAuthBackend)
	if !ok {
		errf("oauth: backend does not support OAuth")
		return exitError
	}
	entry, err := ob.ForceRefresh(context.Background(), key)
	if err != nil {
		errf("%v", err)
		return exitError
	}
	if entry == nil {
		errf("oauth: credential %q is not an OAuth entry", key)
		return exitError
	}
	writeJSON(map[string]any{
		"key":        key,
		"provider":   entry.Provider,
		"expires_at": entry.ExpiresAt,
		"status":     "ok",
	})
	return 0
}

// status はエントリの状態を valid / expired / reauth_required で報告する。
// refresh 失敗時はエラー文字列にトークン値を含めず、status は
// reauth_required になる。
func status(args []string, be backend.Backend) int {
	if len(args) < 1 {
		errf("Usage: trustless oauth status <key>")
		return exitUsage
	}
	key := args[0]
	ob, ok := be.(*OAuthBackend)
	if !ok {
		errf("oauth: backend does not support OAuth")
		return exitError
	}
	entry, err := ob.ResolveEntry(context.Background(), key)
	if err != nil {
		errf("%v", err)
		return exitError
	}
	if entry == nil {
		errf("oauth: credential %q is not an OAuth entry", key)
		return exitError
	}
	// access が空（最小化エントリ・非永続）か失効済みなら refresh を試みる。
	// 失敗時は再認証が必要と報告する。
	if entry.Access == "" || (!entry.ExpiresAt.IsZero() && time.Now().After(entry.ExpiresAt)) {
		if _, err := ob.ForceRefresh(context.Background(), key); err != nil {
			if errors.Is(err, ErrReauthRequired) || errors.Is(err, ErrInvalidGrant) {
				writeJSON(map[string]any{
					"key":                key,
					"provider":           entry.Provider,
					"scopes":             entry.Scopes,
					"expires_at":         formatTime(entry.ExpiresAt),
					"refresh_expires_at": formatTime(entry.RefreshExpiresAt),
					"status":             "reauth_required",
				})
				return 0
			}
			errf("%v", err)
			return exitError
		}
	}
	writeJSON(map[string]any{
		"key":                key,
		"provider":           entry.Provider,
		"scopes":             entry.Scopes,
		"expires_at":         formatTime(entry.ExpiresAt),
		"refresh_expires_at": formatTime(entry.RefreshExpiresAt),
		"status":             "valid",
	})
	return 0
}

// providers は設定済みプロバイダの名前と token_url の一覧を JSON 配列で
// 出力する。client_id / client_secret は出力しない。
func providers(cfg *config.Config) int {
	names := make([]string, 0, len(cfg.OAuth.Providers))
	for name := range cfg.OAuth.Providers {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]map[string]string, 0, len(names))
	for _, name := range names {
		out = append(out, map[string]string{
			"name":      name,
			"token_url": cfg.OAuth.Providers[name].TokenURL,
		})
	}
	writeJSON(out)
	return 0
}

// ProvidersFromConfig は config の Provider 定義を oauth.Provider の map に
// 変換する。main.go の `trustless oauth` 配線とテストから使う。
func ProvidersFromConfig(cfg *config.Config) map[string]Provider {
	out := make(map[string]Provider, len(cfg.OAuth.Providers))
	for name, p := range cfg.OAuth.Providers {
		out[name] = toProvider(name, p)
	}
	return out
}

// toProvider は config の Provider 定義を oauth.Provider に変換する。
func toProvider(name string, p config.OAuthProvider) Provider {
	return Provider{
		Name:              name,
		TokenURL:          p.TokenURL,
		DeviceURL:         p.DeviceURL,
		ClientID:          p.ClientID,
		ClientSecret:      p.ClientSecret,
		Scopes:            p.Scopes,
		TokenRequestStyle: p.TokenRequestStyle,
		DeviceAuthStyle:   p.DeviceAuthStyle,
		Refreshable:       p.Refreshable,
	}
}

// writeJSON は stdout に JSON を 1 行で出力する。
func writeJSON(v any) {
	enc := json.NewEncoder(stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		errf("%v", err)
		os.Exit(exitError)
	}
}
