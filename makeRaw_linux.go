//go:build linux

package main

import (
	"syscall"
	"unsafe"
)

// termiosState is the terminal state prior to entering raw mode.
type termiosState struct {
	termios *syscall.Termios
}

// ioctlTermios runs a termios ioctl (TCGETS/TCSETS) on fd without depending on
// golang.org/x/sys. The request is passed through the raw SYS_IOCTL syscall.
func ioctlTermios(fd int, req uintptr, termios *syscall.Termios) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), req, uintptr(unsafe.Pointer(termios)))
	if errno != 0 {
		return errno
	}
	return nil
}

// makeRaw puts the terminal on fd into raw mode: it disables echo (ECHO),
// line buffering (ICANON), signal generation (ISIG), extended input
// processing (IEXTEN), software flow control (IXON), CR→NL translation
// (ICRNL) and output post-processing (OPOST), and sets VMIN=1 / VTIME=0 so
// reads return one byte at a time. It returns the previous state for
// restoreTerm.
func makeRaw(fd int) (termiosState, error) {
	old := &syscall.Termios{}
	if err := ioctlTermios(fd, syscall.TCGETS, old); err != nil {
		return termiosState{}, err
	}

	raw := *old
	raw.Lflag &^= syscall.ECHO | syscall.ICANON | syscall.ISIG | syscall.IEXTEN
	raw.Iflag &^= syscall.IXON | syscall.ICRNL
	raw.Oflag &^= syscall.OPOST
	raw.Cc[syscall.VMIN] = 1
	raw.Cc[syscall.VTIME] = 0

	if err := ioctlTermios(fd, syscall.TCSETS, &raw); err != nil {
		return termiosState{}, err
	}
	return termiosState{termios: old}, nil
}

// restoreTerm restores the terminal state captured by makeRaw.
func restoreTerm(fd int, state termiosState) {
	if state.termios == nil {
		return
	}
	_ = ioctlTermios(fd, syscall.TCSETS, state.termios)
}
