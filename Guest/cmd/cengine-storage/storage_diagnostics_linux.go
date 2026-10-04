//go:build linux && cengine_storage_diagnostics

package main

import (
	"os"

	"dev.cengine/guest/internal/storagediagnostics"
)

func init() {
	if os.Getpid() == 1 {
		storagediagnostics.Start()
	}
}
