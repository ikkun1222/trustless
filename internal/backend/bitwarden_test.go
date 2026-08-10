package backend

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const testItemsJSON = `[
  {
    "id": "item-1",
    "name": "iria/api/openrouter",
    "type": 2,
    "secureNote": {"type": 0},
    "fields": [
      {"name": "value", "type": 1, "value": "sk-or-v1-secret"}
    ],
    "notes": "created 2026-01-01\nfor openrouter"
  },
  {
    "id": "item-2",
    "name": "gh-api",
    "type": 1,
    "login": {"username": "me", "password": "ghp_githubpass"},
    "fields": [],
    "notes": ""
  },
  {
    "id": "item-3",
    "name": "legacy/key",
    "type": 2,
    "secureNote": {"type": 0},
    "fields": [],
    "notes": "the-value-line\nmeta line"
  },
  {
    "id": "item-4",
    "name": "item/no-value",
    "type": 2,
    "secureNote": {"type": 0},
    "fields": [
      {"name": "other", "type": 1, "value": "x"}
    ],
    "notes": ""
  }
]`

func writeTestFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func TestアイテムマッピングSecureNoteのフィールドから値を取得(t *testing.T) {
	entries, err := parseBWItems([]byte(testItemsJSON))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}

	val, ok := entries["iria/api/openrouter"]
	if !ok || val != "sk-or-v1-secret" {
		t.Fatalf("secureNote value: got %q ok=%v", val, ok)
	}
}

func TestアイテムマッピングLogin型はパスワードを値として扱う(t *testing.T) {
	entries, err := parseBWItems([]byte(testItemsJSON))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	val, ok := entries["gh-api"]
	if !ok || val != "ghp_githubpass" {
		t.Fatalf("login password: got %q ok=%v", val, ok)
	}
}

func TestアイテムマッピングNotes全体を値として扱う多行対応(t *testing.T) {
	entries, err := parseBWItems([]byte(testItemsJSON))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	val, ok := entries["legacy/key"]
	if !ok || val != "the-value-line\nmeta line" {
		t.Fatalf("notes fallback (full notes): got %q ok=%v", val, ok)
	}
}

// 多行の秘密（PEM 等）が notes に格納されている場合、全行を値として返す
// （先頭1行のみに切断されないこと。2026-08-09 oci/api-key の再発防止）。
func TestアイテムマッピングNotesの多行PEMを全行返す(t *testing.T) {
	jsonData := `[
  {
    "id": "pem-1",
    "name": "multiline/pem",
    "type": 2,
    "secureNote": {"type": 0},
    "fields": [],
    "notes": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSj\n-----END PRIVATE KEY-----\n"
  }
]`
	entries, err := parseBWItems([]byte(jsonData))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	val, ok := entries["multiline/pem"]
	if !ok {
		t.Fatalf("key not found")
	}
	want := "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSj\n-----END PRIVATE KEY-----"
	if val != want {
		t.Fatalf("multiline notes: got %q want %q", val, want)
	}
}

func Testアイテムマッピング値が無いアイテムはスキップ(t *testing.T) {
	noValueJSON := `[
  {
    "id": "item-x",
    "name": "item/no-value",
    "type": 2,
    "secureNote": {"type": 0},
    "fields": [
      {"name": "other", "type": 1, "value": "x"}
    ],
    "notes": ""
  }
]`
	entries, err := parseBWItems([]byte(noValueJSON))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if len(entries) != 0 {
		t.Fatalf("expected item without value to be skipped, got %d entries", len(entries))
	}
}

func TestアイテムマッピングJSON不正はエラー(t *testing.T) {
	if _, err := parseBWItems([]byte("{invalid")); err == nil {
		t.Fatalf("expected error for invalid JSON")
	}
}

func Testセッションファイルの保存と読込(t *testing.T) {
	dir := t.TempDir()
	sessionPath := filepath.Join(dir, "bw-session")

	if err := saveSession(sessionPath, "session-key-abc"); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, err := loadSession(sessionPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got != "session-key-abc" {
		t.Fatalf("session: got %q", got)
	}

	info, err := os.Stat(sessionPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("session file perm = %o, want 600", perm)
	}
}

func Testセッションファイルは改行を除去して読込(t *testing.T) {
	dir := t.TempDir()
	sessionPath := writeTestFile(t, dir, "bw-session", "session-key-with-newline\n")

	got, err := loadSession(sessionPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got != "session-key-with-newline" {
		t.Fatalf("session: got %q", got)
	}
}

func Testセッションファイル不存在はエラー(t *testing.T) {
	if _, err := loadSession(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatalf("expected error for missing session file")
	}
}

func Testセッションファイルは上書きしても権限を600に保つ(t *testing.T) {
	dir := t.TempDir()
	sessionPath := writeTestFile(t, dir, "bw-session", "old-session")

	if err := saveSession(sessionPath, "new-session"); err != nil {
		t.Fatalf("save: %v", err)
	}

	info, err := os.Stat(sessionPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("session file perm = %o, want 600", perm)
	}
}

func TestキャッシュTTL24時間以内は有効(t *testing.T) {
	now := time.Now()
	ttl := 24 * time.Hour
	if !cacheFresh(now.Add(-23*time.Hour), now, ttl) {
		t.Fatalf("expected cache within TTL to be fresh")
	}
}

func TestキャッシュTTL24時間超は失効(t *testing.T) {
	now := time.Now()
	ttl := 24 * time.Hour
	if cacheFresh(now.Add(-25*time.Hour), now, ttl) {
		t.Fatalf("expected cache beyond TTL to be stale")
	}
}

func TestキャッシュTTLちょうど24時間は有効(t *testing.T) {
	now := time.Now()
	ttl := 24 * time.Hour
	if !cacheFresh(now.Add(-ttl), now, ttl) {
		t.Fatalf("expected cache at exactly TTL to be fresh")
	}
}

func Testキャッシュタイムスタンプなしは失効(t *testing.T) {
	now := time.Now()
	if cacheFresh(time.Time{}, now, 24*time.Hour) {
		t.Fatalf("expected cache without timestamp to be stale")
	}
}

func Testブートストラップ認証ファイルの読込(t *testing.T) {
	dir := t.TempDir()
	path := writeTestFile(t, dir, "bitwarden-credentials.env", "client_id=abc\nclient_secret=xyz\n")

	clientID, clientSecret, err := loadCredentials(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if clientID != "abc" || clientSecret != "xyz" {
		t.Fatalf("got client_id=%q client_secret=%q", clientID, clientSecret)
	}
}

func Testブートストラップ認証ファイルの改行と空白を除去(t *testing.T) {
	dir := t.TempDir()
	path := writeTestFile(t, dir, "bitwarden-credentials.env", "client_id = abc  \nclient_secret= xyz\n")

	clientID, clientSecret, err := loadCredentials(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if clientID != "abc" || clientSecret != "xyz" {
		t.Fatalf("got client_id=%q client_secret=%q", clientID, clientSecret)
	}
}

func Testブートストラップ認証ファイルの必須キー欠落はエラー(t *testing.T) {
	dir := t.TempDir()
	path := writeTestFile(t, dir, "bitwarden-credentials.env", "client_id=abc\n")

	if _, _, err := loadCredentials(path); err == nil {
		t.Fatalf("expected error when client_secret is missing")
	}
}

func Testブートストラップ認証ファイル不存在はエラー(t *testing.T) {
	if _, _, err := loadCredentials(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatalf("expected error for missing credentials file")
	}
}

func Testバックエンド作成はキャッシュを即時ロードする(t *testing.T) {
	fake := &fakeBW{listOutput: testItemsJSON, listErr: nil}

	be := NewBitwardenBackend(Options{
		SessionPath: filepath.Join(t.TempDir(), "bw-session"),
		runList:     fake.runList,
	})
	if err := be.Load(context.Background()); err != nil {
		t.Fatalf("load: %v", err)
	}

	if fake.listCalls != 1 {
		t.Fatalf("expected exactly 1 list call at load, got %d", fake.listCalls)
	}
	entries, err := be.List(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
}

func Testセッション失効時はキャッシュを使わずfailClosed(t *testing.T) {
	fake := &fakeBW{listOutput: testItemsJSON, listErr: nil, statusErr: errTestSessionExpired}

	be := NewBitwardenBackend(Options{
		SessionPath: filepath.Join(t.TempDir(), "bw-session"),
		runList:     fake.runList,
	})
	if err := be.Load(context.Background()); err != nil {
		t.Fatalf("load: %v", err)
	}
	fake.statusErr = errTestSessionExpired

	if _, err := be.Resolve(context.Background(), "iria/api/openrouter"); err == nil {
		t.Fatalf("expected fail-closed on session expiry")
	}
}

func Testセッション状態はTTL内はbwステータスを1回しか実行しない(t *testing.T) {
	fake := &fakeBW{listOutput: testItemsJSON, listErr: nil}

	be := NewBitwardenBackend(Options{
		SessionPath:     filepath.Join(t.TempDir(), "bw-session"),
		runList:         fake.runList,
		runStatus:       fake.runStatus,
		SessionCheckTTL: time.Hour, // 将来実装: TTL内は status チェックをスキップ
	})
	if err := be.Load(context.Background()); err != nil {
		t.Fatalf("load: %v", err)
	}

	for _, key := range []string{"iria/api/openrouter", "gh-api"} {
		if _, err := be.Resolve(context.Background(), key); err != nil {
			t.Fatalf("resolve %s: %v", key, err)
		}
	}

	if fake.statusCalls != 1 {
		t.Fatalf("expected bw status to run exactly once within TTL, got %d", fake.statusCalls)
	}
}

func Testセッション状態はTTL経過後に再チェックする(t *testing.T) {
	fake := &fakeBW{listOutput: testItemsJSON, listErr: nil}

	be := NewBitwardenBackend(Options{
		SessionPath:     filepath.Join(t.TempDir(), "bw-session"),
		runList:         fake.runList,
		runStatus:       fake.runStatus,
		SessionCheckTTL: time.Nanosecond, // TTL が即失効するため再チェックされる
	})
	if err := be.Load(context.Background()); err != nil {
		t.Fatalf("load: %v", err)
	}

	if _, err := be.Resolve(context.Background(), "iria/api/openrouter"); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if _, err := be.Resolve(context.Background(), "gh-api"); err != nil {
		t.Fatalf("resolve: %v", err)
	}

	if fake.statusCalls < 2 {
		t.Fatalf("expected bw status to re-run after TTL expiry, got %d calls", fake.statusCalls)
	}
}

func Testセッション失効はTTLキャッシュがあってもfailClosedする(t *testing.T) {
	fake := &fakeBW{listOutput: testItemsJSON, listErr: nil, statusErr: errTestSessionExpired}

	be := NewBitwardenBackend(Options{
		SessionPath:     filepath.Join(t.TempDir(), "bw-session"),
		runList:         fake.runList,
		SessionCheckTTL: time.Hour, // 将来実装: キャッシュがあっても失効は必ず fail-closed
	})
	if err := be.Load(context.Background()); err != nil {
		t.Fatalf("load: %v", err)
	}
	fake.statusErr = errTestSessionExpired

	if _, err := be.Resolve(context.Background(), "iria/api/openrouter"); err == nil {
		t.Fatalf("expected fail-closed on session expiry even with TTL cache")
	}
}

func Testアイテム欠落はErrNotFound(t *testing.T) {
	fake := &fakeBW{listOutput: testItemsJSON, listErr: nil}

	be := NewBitwardenBackend(Options{
		SessionPath: filepath.Join(t.TempDir(), "bw-session"),
		runList:     fake.runList,
	})
	if err := be.Load(context.Background()); err != nil {
		t.Fatalf("load: %v", err)
	}

	_, err := be.Resolve(context.Background(), "does/not/exist")
	if _, ok := err.(*ErrNotFound); !ok {
		t.Fatalf("expected ErrNotFound, got %T: %v", err, err)
	}
}

func Testリスト出力のbwエラーはプロパゲート(t *testing.T) {
	fake := &fakeBW{listErr: errTestBwDown}

	be := NewBitwardenBackend(Options{
		SessionPath: filepath.Join(t.TempDir(), "bw-session"),
		runList:     fake.runList,
	})
	if err := be.Load(context.Background()); err == nil {
		t.Fatalf("expected load error when bw list fails")
	}
}

func TestSetValueFieldは既存のhiddenValueフィールドを置換し他を保持(t *testing.T) {
	raw := []byte(`{
	  "id": "item-1",
	  "name": "iria/api/openrouter",
	  "type": 2,
	  "secureNote": {"type": 0},
	  "fields": [
	    {"name": "value", "type": 1, "value": "sk-or-v1-secret"},
	    {"name": "note", "type": 0, "value": "keep-me"}
	  ],
	  "notes": "created 2026-01-01\nfor openrouter",
	  "favorite": true
	}`)

	updated, err := setValueField(raw, "new-secret")
	if err != nil {
		t.Fatalf("setValueField: %v", err)
	}

	var got bwItemFixture
	if err := json.Unmarshal(updated, &got); err != nil {
		t.Fatalf("unmarshal updated item: %v", err)
	}

	checkIdentityFieldsPreserved(t, &got)
	checkValueFieldReplaced(t, &got)
}

// bwItemFixture は setValueField のテストで使う bw item の JSON マッピング。
type bwItemFixture struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Type       int    `json:"type"`
	SecureNote *struct {
		Type int `json:"type"`
	} `json:"secureNote"`
	Fields []struct {
		Name  string `json:"name"`
		Type  int    `json:"type"`
		Value string `json:"value"`
	} `json:"fields"`
	Notes    string `json:"notes"`
	Favorite bool   `json:"favorite"`
}

func checkIdentityFieldsPreserved(t *testing.T, got *bwItemFixture) {
	t.Helper()
	if got.ID != "item-1" || got.Name != "iria/api/openrouter" || got.Type != 2 {
		t.Fatalf("identity fields changed: id=%q name=%q type=%d", got.ID, got.Name, got.Type)
	}
	if got.SecureNote == nil || got.SecureNote.Type != 0 {
		t.Fatalf("secureNote changed: %+v", got.SecureNote)
	}
	if got.Notes != "created 2026-01-01\nfor openrouter" {
		t.Fatalf("notes changed: %q", got.Notes)
	}
	if !got.Favorite {
		t.Fatalf("favorite dropped")
	}
}

func checkValueFieldReplaced(t *testing.T, got *bwItemFixture) {
	t.Helper()
	if len(got.Fields) != 2 {
		t.Fatalf("field count = %d, want 2", len(got.Fields))
	}
	if got.Fields[0].Name != "value" || got.Fields[0].Value != "new-secret" || got.Fields[0].Type != 1 {
		t.Fatalf("value field: %+v", got.Fields[0])
	}
	if got.Fields[1].Name != "note" || got.Fields[1].Value != "keep-me" {
		t.Fatalf("other field changed: %+v", got.Fields[1])
	}
}

func TestSetValueFieldはfieldsが無いアイテムにhiddenValueを追加(t *testing.T) {
	raw := []byte(`{
	  "id": "item-2",
	  "name": "legacy/key",
	  "type": 2,
	  "secureNote": {"type": 0},
	  "notes": "old"
	}`)

	updated, err := setValueField(raw, "new-value")
	if err != nil {
		t.Fatalf("setValueField: %v", err)
	}

	var got struct {
		Fields []struct {
			Name  string `json:"name"`
			Type  int    `json:"type"`
			Value string `json:"value"`
		} `json:"fields"`
		Notes string `json:"notes"`
	}
	if err := json.Unmarshal(updated, &got); err != nil {
		t.Fatalf("unmarshal updated item: %v", err)
	}
	if len(got.Fields) != 1 {
		t.Fatalf("field count = %d, want 1", len(got.Fields))
	}
	f := got.Fields[0]
	if f.Name != "value" || f.Value != "new-value" || f.Type != 1 {
		t.Fatalf("appended field = %+v, want hidden type=1 name=value", f)
	}
	if got.Notes != "old" {
		t.Fatalf("notes changed: %q", got.Notes)
	}
}

func TestSetItemJSONはsecureNoteとhiddenValueフィールドを生成(t *testing.T) {
	payload := setItemJSON("new/key", "sekrit")
	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}

	var got struct {
		Type       int `json:"type"`
		SecureNote struct {
			Type int `json:"type"`
		} `json:"secureNote"`
		Name   string `json:"name"`
		Fields []struct {
			Name  string `json:"name"`
			Type  int    `json:"type"`
			Value string `json:"value"`
		} `json:"fields"`
	}
	if err := json.Unmarshal(decoded, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Type != itemTypeSecureNote {
		t.Fatalf("type = %d, want %d (secureNote)", got.Type, itemTypeSecureNote)
	}
	if got.Name != "new/key" {
		t.Fatalf("name = %q", got.Name)
	}
	if len(got.Fields) != 1 {
		t.Fatalf("field count = %d, want 1", len(got.Fields))
	}
	f := got.Fields[0]
	if f.Name != "value" || f.Type != fieldTypeHidden || f.Value != "sekrit" {
		t.Fatalf("field = %+v, want hidden type=1 name=value", f)
	}
}

func TestSetItemJSONはエンコード値が元のvalueと一致(t *testing.T) {
	const want = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSj\n-----END PRIVATE KEY-----"
	payload := setItemJSON("multiline/pem", want)
	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}

	var got struct {
		Fields []struct {
			Name  string `json:"name"`
			Type  int    `json:"type"`
			Value string `json:"value"`
		} `json:"fields"`
	}
	if err := json.Unmarshal(decoded, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.Fields) != 1 || got.Fields[0].Value != want {
		t.Fatalf("round-trip value mismatch: got %q, want %q", got.Fields[0].Value, want)
	}
}

func TestSetは新しいキーでbwCreateItemを呼びキャッシュを更新する(t *testing.T) {
	vault := newFakeVault()
	fake := &fakeBW{vault: vault}

	be := NewBitwardenBackend(Options{
		SessionPath: filepath.Join(t.TempDir(), "bw-session"),
		runList:     fake.runList,
		runStatus:   fake.runStatus,
		runExec:     fake.runExec,
	})
	if err := be.Load(context.Background()); err != nil {
		t.Fatalf("load: %v", err)
	}

	if err := be.Set(context.Background(), "new/key", "sekrit-new"); err != nil {
		t.Fatalf("set: %v", err)
	}

	if len(fake.execArgs) != 1 {
		t.Fatalf("expected 1 bw exec call, got %d: %v", len(fake.execArgs), fake.execArgs)
	}
	got := fake.execArgs[0]
	if len(got) != 4 || got[0] != "create" || got[1] != "item" || got[2] != "--encoded" {
		t.Fatalf("create item args = %v", got)
	}
	item := decodeItemPayload(t, got[3])
	if item["name"] != "new/key" {
		t.Fatalf("payload name = %v, want new/key", item["name"])
	}
	fields, _ := item["fields"].([]any)
	if len(fields) != 1 {
		t.Fatalf("payload fields = %v", item["fields"])
	}
	f := fields[0].(map[string]any)
	if f["name"] != "value" || f["value"] != "sekrit-new" {
		t.Fatalf("payload field = %v", f)
	}

	val, err := be.Resolve(context.Background(), "new/key")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if val != "sekrit-new" {
		t.Fatalf("resolve value = %q, want %q", val, "sekrit-new")
	}
}

func TestSetは既存キーでbwGetとbwEditを呼び上書きする(t *testing.T) {
	vault := newFakeVault(map[string]any{
		"id":         "item-1",
		"name":       "existing/key",
		"type":       float64(2),
		"secureNote": map[string]any{"type": float64(0)},
		"fields": []any{
			map[string]any{"name": "value", "type": float64(1), "value": "old-secret"},
		},
		"notes": "",
	})
	fake := &fakeBW{vault: vault}

	be := NewBitwardenBackend(Options{
		SessionPath: filepath.Join(t.TempDir(), "bw-session"),
		runList:     fake.runList,
		runStatus:   fake.runStatus,
		runExec:     fake.runExec,
	})
	if err := be.Load(context.Background()); err != nil {
		t.Fatalf("load: %v", err)
	}

	if err := be.Set(context.Background(), "existing/key", "new-secret"); err != nil {
		t.Fatalf("set: %v", err)
	}

	checkGetEditCalls(t, fake, "item-1", "new-secret")

	val, err := be.Resolve(context.Background(), "existing/key")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if val != "new-secret" {
		t.Fatalf("resolve value = %q, want %q", val, "new-secret")
	}
}

// checkGetEditCalls は Set が get item <id> と edit item <id> --encoded
// （ペイロードの hidden field value が wantValue）を呼んだことを検証する。
func checkGetEditCalls(t *testing.T, fake *fakeBW, id, wantValue string) {
	t.Helper()
	if len(fake.execArgs) != 2 {
		t.Fatalf("expected 2 bw exec calls (get + edit), got %d: %v", len(fake.execArgs), fake.execArgs)
	}
	getArgs := fake.execArgs[0]
	if len(getArgs) != 3 || getArgs[0] != "get" || getArgs[1] != "item" || getArgs[2] != id {
		t.Fatalf("get item args = %v", getArgs)
	}
	editArgs := fake.execArgs[1]
	if len(editArgs) != 5 || editArgs[0] != "edit" || editArgs[1] != "item" || editArgs[2] != id || editArgs[3] != "--encoded" {
		t.Fatalf("edit item args = %v", editArgs)
	}
	item := decodeItemPayload(t, editArgs[4])
	fields, _ := item["fields"].([]any)
	if len(fields) != 1 {
		t.Fatalf("edit payload fields = %v", item["fields"])
	}
	f := fields[0].(map[string]any)
	if f["name"] != "value" || f["value"] != wantValue {
		t.Fatalf("edit payload field = %v", f)
	}
}

func TestSetは失敗時にエラーを返しキャッシュを変更しない(t *testing.T) {
	vault := newFakeVault(map[string]any{
		"id":         "item-1",
		"name":       "existing/key",
		"type":       float64(2),
		"secureNote": map[string]any{"type": float64(0)},
		"fields": []any{
			map[string]any{"name": "value", "type": float64(1), "value": "old-secret"},
		},
		"notes": "",
	})
	fake := &fakeBW{vault: vault}

	be := NewBitwardenBackend(Options{
		SessionPath: filepath.Join(t.TempDir(), "bw-session"),
		runList:     fake.runList,
		runStatus:   fake.runStatus,
		runExec:     fake.runExec,
	})
	if err := be.Load(context.Background()); err != nil {
		t.Fatalf("load: %v", err)
	}

	// runList が失敗するよう差し替えると Set は最初のリスト取得で失敗する
	fake.listErr = errTestBwDown
	if err := be.Set(context.Background(), "existing/key", "new-secret"); err == nil {
		t.Fatalf("expected set error when bw list fails")
	}
	if len(fake.execArgs) != 0 {
		t.Fatalf("bw exec should not be called on list failure, got %v", fake.execArgs)
	}

	// キャッシュは変更されず、既存値のまま Resolve できる
	val, err := be.Resolve(context.Background(), "existing/key")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if val != "old-secret" {
		t.Fatalf("resolve value = %q, want %q", val, "old-secret")
	}
}

var (
	errTestBwDown         = &fakeBWError{msg: "bw not reachable"}
	errTestSessionExpired = &fakeBWError{msg: "not logged in"}
)

type fakeBWError struct{ msg string }

func (e *fakeBWError) Error() string { return e.msg }

type fakeBW struct {
	listOutput  string
	listErr     error
	statusErr   error
	listCalls   int
	statusCalls int

	// vault simulates the bw vault for Set tests; when set, runList marshals
	// the vault and runExec applies create/get/edit to it.
	vault *fakeVault

	execCalls int
	execArgs  [][]string
}

func (f *fakeBW) runList(ctx context.Context) ([]byte, error) {
	f.listCalls++
	if f.vault != nil {
		return f.vault.listJSON(), f.listErr
	}
	return []byte(f.listOutput), f.listErr
}

func (f *fakeBW) runStatus(ctx context.Context) ([]byte, error) {
	f.statusCalls++
	return nil, f.statusErr
}

// runExec records the bw command and, when a vault is configured, applies it
// to the simulated vault like the real bw CLI would.
func (f *fakeBW) runExec(ctx context.Context, args []string) ([]byte, error) {
	f.execCalls++
	f.execArgs = append(f.execArgs, append([]string(nil), args...))
	if f.vault != nil {
		return f.vault.exec(args)
	}
	return nil, nil
}

// fakeVault simulates a minimal bw vault for Set tests: runList serializes
// the item list, and exec applies `bw create/get/edit item`.
type fakeVault struct {
	items []map[string]any
	next  int
}

func newFakeVault(items ...map[string]any) *fakeVault {
	return &fakeVault{items: append([]map[string]any(nil), items...)}
}

func (v *fakeVault) listJSON() []byte {
	out, _ := json.Marshal(v.items)
	return out
}

func (v *fakeVault) findID(id string) int {
	for i, it := range v.items {
		if it["id"] == id {
			return i
		}
	}
	return -1
}

func (v *fakeVault) exec(args []string) ([]byte, error) {
	switch args[0] {
	case "create":
		item, err := decodeItemPayloadRaw(args[len(args)-1])
		if err != nil {
			return nil, err
		}
		v.next++
		item["id"] = fmt.Sprintf("item-%d", v.next)
		v.items = append(v.items, item)
		return nil, nil
	case "get":
		i := v.findID(args[2])
		if i < 0 {
			return nil, &fakeBWError{msg: "bw get: item not found"}
		}
		return json.Marshal(v.items[i])
	case "edit":
		item, err := decodeItemPayloadRaw(args[len(args)-1])
		if err != nil {
			return nil, err
		}
		id := args[2]
		item["id"] = id
		if i := v.findID(id); i >= 0 {
			v.items[i] = item
		} else {
			v.items = append(v.items, item)
		}
		return nil, nil
	default:
		return nil, &fakeBWError{msg: "unexpected bw command " + args[0]}
	}
}

func decodeItemPayload(t *testing.T, payload string) map[string]any {
	t.Helper()
	item, err := decodeItemPayloadRaw(payload)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	return item
}

func decodeItemPayloadRaw(payload string) (map[string]any, error) {
	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, err
	}
	var item map[string]any
	if err := json.Unmarshal(raw, &item); err != nil {
		return nil, err
	}
	return item, nil
}

func Testコマンド成功はbw実行を返す(t *testing.T) {
	cmd := buildBWCommand("bw", []string{"list", "items"}, "SESSION")
	if cmd == nil {
		t.Fatalf("expected cmd")
	}
	if len(cmd.Args) != 3 || cmd.Args[1] != "list" || cmd.Args[2] != "items" {
		t.Fatalf("unexpected args: %v", cmd.Args)
	}
	found := false
	for _, kv := range cmd.Env {
		if kv == "BW_SESSION=SESSION" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("BW_SESSION not set in env: %v", cmd.Env)
	}
	// The session value must appear only in BW_SESSION, never elsewhere.
	for _, kv := range cmd.Env {
		if !strings.Contains(kv, "=SESSION") {
			continue
		}
		if !strings.HasPrefix(kv, "BW_SESSION=") {
			t.Fatalf("session leaked in env var: %q", kv)
		}
	}
}

func Testセッション失効判定はプロンプト要求も検知する(t *testing.T) {
	cases := []struct {
		name string
		msg  string
		want bool
	}{
		{"not logged in", "bw list: exit status 1: You are not logged in.", true},
		{"invalid session", "bw list: exit status 1: Invalid session.", true},
		{"master password prompt", "bw list: exit status 1: ? Master password: [input is hidden]", true},
		{"network error", "bw list: exit status 1: connect: connection refused", false},
		{"timeout", "bw list: signal: killed", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isSessionErr(&bwError{msg: tc.msg}); got != tc.want {
				t.Fatalf("isSessionErr(%q) = %v, want %v", tc.msg, got, tc.want)
			}
		})
	}
}

func Testセッション状態キャッシュは並行Resolveで安全(t *testing.T) {
	fake := &fakeBW{listOutput: testItemsJSON, listErr: nil}

	be := NewBitwardenBackend(Options{
		SessionPath:     filepath.Join(t.TempDir(), "bw-session"),
		runList:         fake.runList,
		runStatus:       fake.runStatus,
		SessionCheckTTL: time.Hour,
	})
	if err := be.Load(context.Background()); err != nil {
		t.Fatalf("load: %v", err)
	}

	const goroutines = 16
	const iters = 50
	keys := []string{"iria/api/openrouter", "gh-api", "legacy/key"}
	var wg sync.WaitGroup
	errCh := make(chan error, goroutines*iters)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				key := keys[(g+i)%len(keys)]
				if _, err := be.Resolve(context.Background(), key); err != nil {
					errCh <- fmt.Errorf("resolve %s: %w", key, err)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
}
