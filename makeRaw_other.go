//go:build !linux

package main

import "errors"

// errRawModeUnsupported is returned by makeRaw on non-Linux platforms, where
// raw-mode terminal handling via syscall termios is unavailable.
var errRawModeUnsupported = errors.New("raw terminal mode is not supported on this platform")

// termiosState is a placeholder on non-Linux platforms, where raw-mode
// terminal handling is unsupported and password input falls back to plain
// line reads (echo may be visible).
type termiosState struct{}

// makeRaw is not supported on non-Linux platforms. readPassword() falls back
// to reading a plain line from stdin, so this is never called; the error is
// returned defensively.
func makeRaw(fd int) (termiosState, error) {
	return termiosState{}, errRawModeUnsupported
}

// restoreTerm is a no-op on non-Linux platforms.
func restoreTerm(fd int, state termiosState) {}
