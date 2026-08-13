package proxy

import "sync"

// Secrets holds the known secret values used for outbound DLP scanning.
// It is safe for concurrent use: the proxy reads a snapshot on every
// request while a background hot-reload may Replace the whole set at any
// time without blocking or racing in-flight scans.
type Secrets struct {
	mu   sync.RWMutex
	vals []string
}

// NewSecrets returns a Secrets set initialized with vals.
func NewSecrets(vals []string) *Secrets {
	return &Secrets{vals: vals}
}

// Replace atomically swaps the entire secret set (hot reload).
func (s *Secrets) Replace(vals []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.vals = vals
}

// Snapshot returns a copy of the current values for scanning. Copying a
// few dozen strings per request is negligible compared to body scanning.
func (s *Secrets) Snapshot() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, len(s.vals))
	copy(out, s.vals)
	return out
}

// Len reports the number of known secrets (for logs).
func (s *Secrets) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.vals)
}
