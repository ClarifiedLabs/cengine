package main

import (
	"errors"
	"fmt"

	"dev.cengine/guest/internal/storageboot"
)

// shutdownStorage is the single PID1 poweroff gate. run returns only after
// private-owner EOF or fatal pre-Ready boot termination and joins owned workers.
// An uncertain result carries its owners to PID1's containment loop. Ordinary
// service/protocol errors are diagnostic, not evidence of an uncertain reap.
// This seam permits unit tests without a real mount, worker, or reboot syscall.
func shutdownStorage(run, closeRoots, closeDisks, poweroff func() error) error {
	terminal := run()
	if errors.Is(terminal, storageboot.ErrShutdownUncertain) {
		return terminal
	}
	for _, step := range []struct {
		name string
		call func() error
	}{{"close roots", closeRoots}, {"close disks", closeDisks}, {"poweroff", poweroff}} {
		if err := step.call(); err != nil {
			return errors.Join(terminal, fmt.Errorf("storage shutdown %s: %w", step.name, err))
		}
	}
	return nil
}
