package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEventMarshalは固定フィールド順とUTCタイムスタンプで出力する(t *testing.T) {
	ev := Event{
		TS:      time.Date(2026, 8, 14, 1, 2, 3, 456000000, time.FixedZone("JST", 9*3600)),
		Event:   ProxyInject,
		Key:     "iria/api/xai",
		Host:    "api.x.ai",
		Verdict: VerdictInject,
		Detail:  "header=Authorization",
	}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"ts":"2026-08-13T16:02:03.456Z","event":"proxy.inject","key":"iria/api/xai","host":"api.x.ai","verdict":"inject","detail":"header=Authorization"}`
	if string(b) != want {
		t.Errorf("got  %s\nwant %s", b, want)
	}
}

func TestEventMarshalは空フィールドをomitemptyする(t *testing.T) {
	b, err := json.Marshal(Event{TS: time.Unix(0, 0).UTC(), Event: DlpRedact, Verdict: VerdictRedact})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "key") || strings.Contains(string(b), "host") || strings.Contains(string(b), "detail") {
		t.Errorf("empty fields should be omitted: %s", b)
	}
}

func TestOffSinkはnoop(t *testing.T) {
	s := Off()
	s.Emit(Event{Event: ProxyInject})
	s.Close()
}

func TestNewはsink種別を切り替える(t *testing.T) {
	if _, ok := New("journald", "", 0).(*stdoutSink); !ok {
		t.Error("journald should return stdoutSink")
	}
	if _, ok := New("off", "", 0).(*offSink); !ok {
		t.Error("off should return offSink")
	}
	if _, ok := New("", "", 0).(*offSink); !ok {
		t.Error("empty should return offSink")
	}
	if _, ok := New("file", filepath.Join(t.TempDir(), "a.jsonl"), 0).(*fileSink); !ok {
		t.Error("file should return fileSink")
	}
}

func TestFileSinkは0600で作成しJSONLを書き込む(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	s := NewFile(path, 16)
	defer s.Close()

	s.Emit(Event{TS: time.Now(), Event: ProxyInject, Key: "iria/api/xai", Verdict: VerdictInject})
	s.Emit(Event{TS: time.Now(), Event: DlpRedact, Verdict: VerdictRedact, Detail: "changed=2"})
	// worker が両イベントを書き込むのを待つ（Size()>0 だけで切ると
	// 非同期 worker が1行目のみ書いた時点で読んでしまうため）
	deadline := time.Now().Add(2 * time.Second)
	for {
		if data, err := os.ReadFile(path); err == nil && strings.Count(string(data), "\n") >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("both events not written within 2s")
		}
		time.Sleep(10 * time.Millisecond)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %04o, want 0600", fi.Mode().Perm())
	}

	data, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2: %q", len(lines), data)
	}
	var ev Event
	if err := json.Unmarshal([]byte(lines[0]), &ev); err != nil {
		t.Fatalf("line not JSON: %v", err)
	}
	if ev.Event != ProxyInject {
		t.Errorf("event = %q, want proxy.inject", ev.Event)
	}
}

func TestFileSinkはバッファ超過でdropする(t *testing.T) {
	dir := t.TempDir()
	s := NewFile(filepath.Join(dir, "audit.jsonl"), 2)
	defer s.Close()
	for i := 0; i < 100; i++ {
		s.Emit(Event{Event: RunSpawn})
	}
	// worker が尽きるのを待つ
	deadline := time.Now().Add(2 * time.Second)
	for {
		if s.Dropped() > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no drop observed")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if s.Dropped() == 0 {
		t.Error("expected dropped > 0")
	}
}

func TestFileSinkのReopenは新ファイルに書き込む(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	s := NewFile(path, 16)
	defer s.Close()

	s.Emit(Event{Event: ProxyInject})
	// 書込完了を待つ
	waitFor := func() {
		deadline := time.Now().Add(2 * time.Second)
		for {
			if fi, err := os.Stat(path); err == nil && fi.Size() > 0 {
				return
			}
			if time.Now().After(deadline) {
				t.Fatal("write timeout")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	waitFor()

	// logrotate 相当: リネーム → Reopen → 新ファイル生成
	rotated := path + ".1"
	os.Rename(path, rotated)
	s.Reopen()

	s.Emit(Event{Event: DlpDeny})
	waitFor()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reopened file not created: %v", err)
	}
	if !strings.Contains(string(data), `"event":"dlp.deny"`) {
		t.Errorf("reopened file missing new event: %q", data)
	}
	if n, _ := os.ReadFile(rotated); !strings.Contains(string(n), `"event":"proxy.inject"`) {
		t.Error("rotated file should keep old events")
	}
}

func TestFileSinkは開けない場合noopでClose安全(t *testing.T) {
	// 存在しないディレクトリ配下 → open 失敗
	s := NewFile(filepath.Join(t.TempDir(), "no-such-dir", "audit.jsonl"), 0)
	s.Emit(Event{Event: ProxyInject})
	s.Close()
}

func TestDefaultFileはホーム展開される(t *testing.T) {
	if !strings.HasPrefix(expandHome(DefaultFile), "/") {
		t.Errorf("expandHome should expand ~: %q", expandHome(DefaultFile))
	}
}
