// Package audit implements structured audit logging for trustless.
//
// Every event (proxy injection/deny, run spawn, DLP scrub/deny, OAuth
// refresh/failure/reauth) is emitted as one JSON line. Sinks are
// journald (stdout JSONL), file (append-only, 0600), or off.
//
// Design rules:
//   - audit never breaks the hot path: Emit is async (buffered channel),
//     drops events when the buffer is full, and swallows all I/O errors.
//   - secrets never appear in events: only key names, hosts, verdicts,
//     and small detail strings (never token/secret values).
package audit

import (
	"encoding/json"
	"time"
)

// Event is a single structured audit record.
type Event struct {
	TS      time.Time
	Event   string
	Key     string
	Host    string
	Verdict string
	Detail  string
}

// Event names.
const (
	ProxyInject         = "proxy.inject"
	ProxyDeny           = "proxy.deny"
	RunSpawn            = "run.spawn"
	DlpRedact           = "dlp.redact"
	DlpDeny             = "dlp.deny"
	OAuthRefresh        = "oauth.refresh"
	OAuthFail           = "oauth.fail"
	OAuthReauthRequired = "oauth.reauth_required"
)

// Verdicts.
const (
	VerdictInject         = "inject"
	VerdictDeny           = "deny"
	VerdictSpawn          = "spawn"
	VerdictRedact         = "redact"
	VerdictRefresh        = "refresh"
	VerdictFail           = "fail"
	VerdictReauthRequired = "reauth_required"
)

// Sink receives audit events. Implementations must never block or fail the
// caller: Emit is called on the request hot path.
type Sink interface {
	Emit(Event)
	Close()
}

// New builds a sink from config values. sinkKind is "journald", "file",
// "off", or "" (empty → off). file is the path for "file"; an empty path
// falls back to DefaultFile. buffer is the async buffer size (<=0 → default).
func New(sinkKind, file string, buffer int) Sink {
	switch sinkKind {
	case "journald":
		return &stdoutSink{}
	case "file":
		return NewFile(file, buffer)
	default:
		return Off()
	}
}

// DefaultFile is the XDG state path used when [audit] sink = "file"
// and no explicit file is configured.
const DefaultFile = "~/.local/state/trustless/audit.jsonl"

// MarshalJSON renders the event with a UTC RFC3339Nano timestamp and the
// fixed field order ts, event, key, host, verdict, detail.
func (e Event) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		TS      string `json:"ts"`
		Event   string `json:"event"`
		Key     string `json:"key,omitempty"`
		Host    string `json:"host,omitempty"`
		Verdict string `json:"verdict,omitempty"`
		Detail  string `json:"detail,omitempty"`
	}{
		TS:      e.TS.UTC().Format(time.RFC3339Nano),
		Event:   e.Event,
		Key:     e.Key,
		Host:    e.Host,
		Verdict: e.Verdict,
		Detail:  e.Detail,
	})
}
