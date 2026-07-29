package setup

import (
	"fmt"
	"os/exec"
)

func InitPassStore(gpgKeyID string) error {
	if _, err := exec.LookPath("pass"); err != nil {
		return fmt.Errorf("pass is not available: install it with your package manager (e.g., apt install pass, brew install pass, pacman -S pass)")
	}

	if err := exec.Command("pass", "init", gpgKeyID).Run(); err != nil {
		return fmt.Errorf("pass init failed: %w", err)
	}

	if err := exec.Command("pass", "git", "init").Run(); err != nil {
		return fmt.Errorf("pass git init failed: %w", err)
	}

	return nil
}
