//go:build linux

package main

import (
	"encoding/hex"
	"log"
	"net"
	"os"
	"strconv"

	"dev.cengine/guest/internal/boot"
	"dev.cengine/guest/internal/disk"
	guestnetwork "dev.cengine/guest/internal/network"
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
	managementAddress, err := boot.KernelParameter("cengine.management_address")
	if err != nil {
		log.Fatal(err)
	}
	managementVLAN, err := boot.KernelParameter("cengine.management_vlan")
	if err != nil {
		log.Fatal(err)
	}
	vlan, err := strconv.ParseUint(managementVLAN, 10, 16)
	if err != nil {
		log.Fatalf("parse management VLAN: %v", err)
	}
	if err := guestnetwork.ConfigureManagement(managementAddress, uint16(vlan)); err != nil {
		log.Fatalf("configure management network: %v", err)
	}
	managementIP, _, err := net.ParseCIDR(managementAddress)
	if err != nil {
		log.Fatalf("parse management address: %v", err)
	}
	go func() {
		if err := storage.ServeNFS(net.JoinHostPort(managementIP.String(), "2049"), "/data/volumes"); err != nil {
			log.Fatalf("serve NFS volume store: %v", err)
		}
	}()
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
	if err := storage.Serve(listener, "/data/volumes", secret); err != nil {
		log.Fatalf("serve volume store: %v", err)
	}
}

func volumeSecret() ([]byte, error) {
	value, err := boot.KernelParameter("cengine.volume_secret")
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(value)
}
