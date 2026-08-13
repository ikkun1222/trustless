package audit

import (
	"encoding/json"
	"fmt"
	"os"
)

// stdoutSink writes JSONL to stdout (systemd journald captures it when the
// unit uses StandardOutput=journal). Synchronous: serve emits at low volume.
// Write errors are reported to stderr only — never to the caller.
type stdoutSink struct{}

func (s *stdoutSink) Emit(ev Event) {
	line, err := json.Marshal(ev)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit: marshal: %v\n", err)
		return
	}
	if _, err := fmt.Fprintln(os.Stdout, string(line)); err != nil {
		fmt.Fprintf(os.Stderr, "audit: write: %v\n", err)
	}
}

func (s *stdoutSink) Close() {}

// offSink discards every event.
type offSink struct{}

func (s *offSink) Emit(Event) {}
func (s *offSink) Close()     {}

// Off returns a no-op sink.
func Off() Sink { return &offSink{} }
