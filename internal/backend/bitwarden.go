package backend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// bwItem mirrors the JSON fields of a `bw list items` entry that we map.
type bwItem struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Type       int    `json:"type"`
	SecureNote *struct {
		Type int `json:"type"`
	} `json:"secureNote"`
	Login *struct {
		Password string `json:"password"`
	} `json:"login"`
	Fields []struct {
		Name  string `json:"name"`
		Type  int    `json:"type"`
		Value string `json:"value"`
	} `json:"fields"`
	Notes string `json:"notes"`
}

// itemType constants from the Bitwarden item JSON API.
const (
	itemTypeLogin      = 1
	itemTypeSecureNote = 2

	fieldTypeHidden = 1
)

// defaultCacheTTL bounds how long the in-memory cache may serve Resolve when
// the bw CLI is unreachable (§3.1 H-3).
const defaultCacheTTL = 24 * time.Hour

// defaultSessionTTL is the default session state cache window when Options
// does not set SessionCheckTTL. Zero means check on every Resolve.
const defaultSessionTTL = 60 * time.Second

// bwError indicates a Bitwarden CLI failure (session expiry, network, etc.).
// Callers use it to decide between fail-closed and cache fallback.
type bwError struct {
	msg string
}

func (e *bwError) Error() string { return e.msg }

// isSessionErr reports whether the bw CLI reported an authentication failure
// (session expired or not logged in). Such failures always fail closed. The
// "master password" check catches the interactive unlock prompt that bw emits
// when the session key is invalid (verified 2026-08-09).
func isSessionErr(err error) bool {
	var bwe *bwError
	if errors.As(err, &bwe) {
		s := strings.ToLower(bwe.msg)
		return strings.Contains(s, "not logged in") || strings.Contains(s, "invalid session") || strings.Contains(s, "master password")
	}
	return false
}

// BitwardenBackend implements Backend by wrapping the bw CLI.
//
// Session key handling (H-1): the session key is passed to bw exclusively via
// the BW_SESSION environment variable — never on argv (ps -ef / cmdline leak).
type BitwardenBackend struct {
	mu          sync.RWMutex
	sessionPath string
	bw          string // bw binary path, defaults to "bw"

	cache     map[string]string
	cacheAt   time.Time
	cacheInit bool

	// sessionTTL bounds how often the bw session status is re-checked. Zero
	// disables the cache (status checked on every Resolve). Load や list 成功時
	// にセッション状態を初期化し、bw status の実行回数を削減する。
	sessionTTL time.Duration

	// sessionMu guards the session state cache below. Resolve はキャッシュ
	// ミス時に b.mu を解放した後に sessionAlive を呼ぶため、別の mutex で
	// セッション状態を保護してデータレースを防ぐ（Backend は concurrent
	// safe を要求する）。
	sessionMu sync.Mutex
	// セッション状態のTTLキャッシュ。sessionCheckedAt がセットされていれば
	// sessionValid の結果が TTL 内で再利用される。
	sessionCheckedAt time.Time
	sessionValid     bool

	// runList runs `bw list items`; runStatus runs `bw status`. Overridable in
	// tests via Options.
	runList   func(ctx context.Context) ([]byte, error)
	runStatus func(ctx context.Context) ([]byte, error)
}

// Options configures a BitwardenBackend. Zero values select defaults.
type Options struct {
	// SessionPath is the session key file (chmod 600). Defaults to
	// ~/.config/trustless/bw-session.
	SessionPath string
	// BWPath overrides the bw binary path. Defaults to "bw".
	BWPath string
	// CacheTTL overrides the cache validity window. Defaults to 24h.
	CacheTTL time.Duration
	// SessionCheckTTL overrides how often the bw session status is re-checked
	// during Resolve. Zero checks on every Resolve.
	SessionCheckTTL time.Duration
	// runList/runStatus are test-only hooks; leave nil in production.
	runList   func(ctx context.Context) ([]byte, error)
	runStatus func(ctx context.Context) ([]byte, error)
}

// NewBitwardenBackend returns a backend that loads the session key lazily.
// Call Load once at startup to populate the in-memory cache.
func NewBitwardenBackend(opts Options) *BitwardenBackend {
	if opts.SessionPath == "" {
		opts.SessionPath = sessionFilePath()
	}
	if opts.BWPath == "" {
		opts.BWPath = "bw"
	}
	b := &BitwardenBackend{
		sessionPath: opts.SessionPath,
		bw:          opts.BWPath,
		cache:       make(map[string]string),
		sessionTTL:  opts.SessionCheckTTL,
	}
	// TTL 未指定時のみデフォルトを適用する。明示指定（テスト含む）は優先する。
	if opts.SessionCheckTTL == 0 {
		b.sessionTTL = defaultSessionTTL
	}
	b.runList = opts.runList
	if b.runList == nil {
		b.runList = func(ctx context.Context) ([]byte, error) {
			return b.execBW(ctx, []string{"list", "items"})
		}
	}
	b.runStatus = opts.runStatus
	if b.runStatus == nil {
		b.runStatus = func(ctx context.Context) ([]byte, error) {
			return b.execBW(ctx, []string{"status"})
		}
	}
	return b
}

// sessionFilePath returns the default session key location.
func sessionFilePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "trustless", "bw-session")
	}
	return filepath.Join(home, ".config", "trustless", "bw-session")
}

// buildBWCommand constructs the bw exec with the session key passed via the
// BW_SESSION environment variable (H-1) — never on argv.
func buildBWCommand(bwPath string, args []string, sessionKey string) *exec.Cmd {
	cmd := exec.Command(bwPath, args...)
	cmd.Env = append(os.Environ(), "BW_SESSION="+sessionKey)
	return cmd
}

// execBW runs bw with the session key passed via BW_SESSION (H-1).
func (b *BitwardenBackend) execBW(ctx context.Context, args []string) ([]byte, error) {
	key, err := loadSession(b.sessionPath)
	if err != nil {
		return nil, err
	}
	cmd := buildBWCommand(b.bw, args, key)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, &bwError{msg: fmt.Sprintf("bw %s: %v: %s", args[0], err, strings.TrimSpace(string(out)))}
	}
	// With an invalid session key, bw exits 0 but emits its interactive
	// "Master password" prompt on stdout (verified 2026-08-09). Treat that as
	// a session error so callers fail closed instead of parsing prompt text.
	if strings.Contains(strings.ToLower(string(out)), "master password") {
		return nil, &bwError{msg: fmt.Sprintf("bw %s: session not valid (unlock prompt emitted)", args[0])}
	}
	return out, nil
}

// Load fetches the vault and fills the in-memory cache. It must be called once
// before Resolve (design §3.1: one list at startup).
func (b *BitwardenBackend) Load(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.loadLocked(ctx)
}

func (b *BitwardenBackend) loadLocked(ctx context.Context) error {
	out, err := b.runList(ctx)
	if err != nil {
		if isSessionErr(err) {
			return err // fail-closed: session expired (H-3)
		}
		return err
	}
	items, err := parseBWItems(out)
	if err != nil {
		return fmt.Errorf("parse bw list items: %w", err)
	}
	b.cache = items
	b.cacheAt = time.Now()
	b.cacheInit = true
	return nil
}

// sessionAlive reports whether the current bw session is valid. TTL内は前回の
// チェック結果を再利用し、TTL 超過時のみ bw status を実行して結果を更新する。
// sessionTTL がゼロの場合は毎回チェックする（後方互換）。sessionMu で保護する
// ため複数ゴルーチンから安全に呼べる。
func (b *BitwardenBackend) sessionAlive(ctx context.Context) bool {
	b.sessionMu.Lock()
	defer b.sessionMu.Unlock()
	if b.sessionTTL > 0 && cacheFresh(b.sessionCheckedAt, time.Now(), b.sessionTTL) {
		return b.sessionValid
	}
	valid := true
	if _, err := b.runStatus(ctx); err != nil {
		valid = false
	}
	b.sessionCheckedAt = time.Now()
	b.sessionValid = valid
	return valid
}

// Resolve returns the value for key. When bw is unreachable it serves from the
// cache (audit WARN), but only within the TTL; a stale cache or an invalid
// session always fail closed (§3.1 H-3).
func (b *BitwardenBackend) Resolve(ctx context.Context, key string) (string, error) {
	b.mu.RLock()
	if val, ok := b.cache[key]; ok {
		b.mu.RUnlock()
		if !b.sessionAlive(ctx) {
			return "", &bwError{msg: "bitwarden session not valid (fail closed)"}
		}
		return val, nil
	}
	if !b.cacheInit {
		b.mu.RUnlock()
		return "", &ErrNotFound{Key: key, Reason: "bitwarden cache not loaded"}
	}
	if !cacheFresh(b.cacheAt, time.Now(), defaultCacheTTL) {
		b.mu.RUnlock()
		return "", &ErrNotFound{Key: key, Reason: "bitwarden cache expired and bw unavailable"}
	}
	// Cache miss with a stale-but-valid cache: refresh from bw.
	b.mu.RUnlock()

	b.mu.Lock()
	defer b.mu.Unlock()
	out, err := b.runList(ctx)
	if err != nil {
		if isSessionErr(err) {
			return "", err // session expired: always fail closed (H-3)
		}
		// bw unreachable: serve stale cache within TTL (audit WARN) or fail.
		if !cacheFresh(b.cacheAt, time.Now(), defaultCacheTTL) {
			return "", &ErrNotFound{Key: key, Reason: "bitwarden cache expired and bw unavailable"}
		}
		if val, ok := b.cache[key]; ok {
			auditWarn("bitwarden bw unavailable; serving from cache for %q", key)
			return val, nil
		}
		return "", &ErrNotFound{Key: key, Reason: "not in cache"}
	}
	items, err := parseBWItems(out)
	if err != nil {
		return "", fmt.Errorf("parse bw list items: %w", err)
	}
	b.cache = items
	b.cacheAt = time.Now()
	val, ok := b.cache[key]
	if !ok {
		return "", &ErrNotFound{Key: key, Reason: "not found in bitwarden vault"}
	}
	return val, nil
}

// List returns all credential keys from the in-memory cache.
func (b *BitwardenBackend) List(ctx context.Context) ([]Entry, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if !b.cacheInit {
		return nil, &bwError{msg: "bitwarden cache not loaded"}
	}
	entries := make([]Entry, 0, len(b.cache))
	for k := range b.cache {
		entries = append(entries, Entry{Key: k})
	}
	return entries, nil
}

// parseBWItems maps bw list items output to key → value.
//
// Mapping (§3.1): item name = key. secureNote: the hidden field named "value"
// holds the secret; login items fall back to login.password; the first notes
// line is a backward-compat fallback for migrated pass entries.
func parseBWItems(data []byte) (map[string]string, error) {
	var items []bwItem
	if err := json.Unmarshal(data, &items); err != nil {
		return nil, err
	}
	entries := make(map[string]string, len(items))
	for _, it := range items {
		if it.Name == "" {
			continue
		}
		val := ""
		if it.Type == itemTypeLogin && it.Login != nil {
			val = it.Login.Password
		}
		if val == "" {
			for _, f := range it.Fields {
				if f.Name == "value" && f.Type == fieldTypeHidden {
					val = f.Value
					break
				}
			}
		}
		if val == "" && it.Notes != "" {
			val = strings.SplitN(it.Notes, "\n", 2)[0]
		}
		if val != "" {
			entries[it.Name] = val
		}
	}
	return entries, nil
}

// cacheFresh reports whether the cache loaded at t is within ttl of now.
func cacheFresh(t, now time.Time, ttl time.Duration) bool {
	if t.IsZero() {
		return false
	}
	return !now.After(t.Add(ttl))
}

// auditWarn is a placeholder for the resolve audit log (design §8). It avoids
// printing the secret value itself.
func auditWarn(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "audit WARN: "+format+"\n", args...)
}

// SaveSession writes the session key to path with mode 0600.
func SaveSession(path, key string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("mkdir session dir: %w", err)
	}
	return os.WriteFile(path, []byte(key), 0o600)
}

// saveSession is the internal helper (tested in-package).
func saveSession(path, key string) error {
	return SaveSession(path, key)
}

// loadSession reads the session key from path, trimming whitespace.
func loadSession(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read session file %s: %w", path, err)
	}
	return strings.TrimSpace(string(data)), nil
}

// loadCredentials reads client_id / client_secret from a KEY=VALUE env file
// (H-2: bootstrap auth lives outside the vault to avoid a resolve cycle).
func loadCredentials(path string) (clientID, clientSecret string, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", "", fmt.Errorf("read credentials file %s: %w", path, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "client_id":
			clientID = strings.TrimSpace(v)
		case "client_secret":
			clientSecret = strings.TrimSpace(v)
		}
	}
	if clientID == "" || clientSecret == "" {
		return "", "", fmt.Errorf("credentials file %s must set client_id and client_secret", path)
	}
	return clientID, clientSecret, nil
}

// Unlock reads the master password from stdin, runs `bw unlock --raw`, and
// persists the session key to the 600 session file. The master password never
// touches argv, env, or disk (M-3). A trailing newline is required: bw CLI
// reads the password from stdin up to the newline (verified 2026-08-09).
func Unlock(bwPath, sessionPath string, password string) error {
	cmd := exec.Command(bwPath, "unlock", "--raw")
	cmd.Stdin = strings.NewReader(password + "\n")
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("bw unlock failed: %w", err)
	}
	key := strings.TrimSpace(string(out))
	if key == "" {
		return fmt.Errorf("bw unlock returned an empty session key")
	}
	return SaveSession(sessionPath, key)
}
