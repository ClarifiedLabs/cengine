//go:build darwin && cgo

// cengine-storage-controller has no diagnostic stdout and no private-key transport.
package main

import (
	"context"
	"dev.cengine/guest/internal/storagebootstrap"
	"os"
)

func main() {
	if !validLifecycleArguments(os.Args) {
		os.Exit(64)
	}
	if storagebootstrap.RunLifecycleChild(context.Background()) != nil {
		os.Exit(1)
	}
}

func validLifecycleArguments(args []string) bool {
	return len(args) == 1 || (len(args) == 2 && args[1] == "--lifecycle-v2")
}
