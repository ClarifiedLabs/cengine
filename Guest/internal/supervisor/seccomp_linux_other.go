//go:build linux && !arm64

package supervisor

import "fmt"

func applyDefaultSeccomp(enabled bool, _ uint64) error {
	if !enabled {
		return nil
	}
	return fmt.Errorf("the Docker default seccomp profile is only available for arm64 guests")
}
