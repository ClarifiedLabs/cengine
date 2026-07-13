//go:build linux

package main

import (
	"encoding/hex"
	"log"
	"os"
	"strings"

	"dev.cengine/guest/internal/boot"
	"dev.cengine/guest/internal/disk"
	"dev.cengine/guest/internal/protocol"
	"dev.cengine/guest/internal/storage"
	"dev.cengine/guest/internal/vsock"
)

func main() {
	if os.Getpid() != 1 {
		log.Fatal("cengine-storage must run as PID 1")
	}
	if err := boot.MountKernelFilesystems(); err != nil {
		log.Fatalf("mount kernel filesystems: %v", err)
	}
	if err := disk.EnsureExt4("/dev/vda", "/data", "cengine-volumes"); err != nil {
		log.Fatalf("prepare volume disk: %v", err)
	}
	cid, err := vsock.LocalCID()
	if err != nil {
		log.Fatalf("resolve local vsock CID: %v", err)
	}
	listener, err := vsock.Listen(protocol.FileSystemPort)
	if err != nil {
		log.Fatalf("listen on filesystem vsock: %v", err)
	}
	defer listener.Close()
	log.Printf("storage vsock ready on %d:%d", cid, protocol.FileSystemPort)
	secret, err := volumeSecret()
	if err != nil {
		log.Fatalf("load volume token secret: %v", err)
	}
	if err := storage.Serve(listener, "/data", secret); err != nil {
		log.Fatalf("serve volume store: %v", err)
	}
}

func volumeSecret() ([]byte, error) {
	data, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return nil, err
	}
	for _, value := range strings.Fields(string(data)) {
		if strings.HasPrefix(value, "cengine.volume_secret=") {
			return hex.DecodeString(strings.TrimPrefix(value, "cengine.volume_secret="))
		}
	}
	return nil, os.ErrNotExist
}
