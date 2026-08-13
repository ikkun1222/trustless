package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// fileSink appends JSONL events to a file (created 0600), asynchronously.
// Events are buffered; when the buffer is full they are dropped and counted.
// Reopen closes and re-opens the file (SIGHUP / logrotate support).
type fileSink struct {
	mu      sync.Mutex
	ch      chan Event
	dropped int
	f       *os.File
	w       *bufio.Writer
	done    chan struct{}
}

// NewFile returns a file-backed sink. On open failure it returns a disabled
// sink (no-op, Close-safe) so audit never breaks the caller.
func NewFile(path string, buffer int) *fileSink {
	if path == "" {
		path = DefaultFile
	}
	path = expandHome(path)
	if buffer <= 0 {
		buffer = 1024
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		// Fail-open: audit disabled, never break the caller.
		return &fileSink{done: make(chan struct{})}
	}
	s := &fileSink{
		ch:   make(chan Event, buffer),
		f:    f,
		w:    bufio.NewWriter(f),
		done: make(chan struct{}),
	}
	go s.worker()
	return s
}

// Emit queues an event; drops it if the buffer is full.
func (s *fileSink) Emit(ev Event) {
	if s.ch == nil {
		return // disabled sink
	}
	select {
	case s.ch <- ev:
	default:
		s.mu.Lock()
		s.dropped++
		s.mu.Unlock()
	}
}

// Dropped reports how many events were dropped since start/last reset.
func (s *fileSink) Dropped() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dropped
}

// Reopen closes the underlying file and re-opens it (logrotate support).
func (s *fileSink) Reopen() {
	if s.f == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.w.Flush()
	path := s.f.Name()
	s.f.Close()
	if f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
		s.f = f
		s.w = bufio.NewWriter(f)
	}
}

// Close flushes and closes the file, then stops the worker.
func (s *fileSink) Close() {
	if s.done == nil {
		return
	}
	select {
	case <-s.done:
		return
	default:
	}
	close(s.done)
	s.mu.Lock()
	if s.w != nil {
		s.w.Flush()
	}
	if s.f != nil {
		s.f.Close()
	}
	s.mu.Unlock()
}

func (s *fileSink) worker() {
	for ev := range s.ch {
		line, err := json.Marshal(ev)
		if err != nil {
			continue
		}
		s.mu.Lock()
		if s.w != nil {
			s.w.Write(line)
			s.w.WriteByte('\n')
			s.w.Flush()
		}
		s.mu.Unlock()
	}
}

func expandHome(path string) string {
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}
