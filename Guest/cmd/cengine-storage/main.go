//go:build linux

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"strconv"
	"time"

	"dev.cengine/guest/internal/boot"
	"dev.cengine/guest/internal/diskbootstrap"
	guestnetwork "dev.cengine/guest/internal/network"
	"dev.cengine/guest/internal/storageboot"
	"golang.org/x/sys/unix"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--managed-lifecycle-worker" {
		if err := storageboot.RunLifecycleWorker(); err != nil {
			log.Fatalf("managed lifecycle worker: %v", err)
		}
		return
	}
	if os.Getpid() != 1 {
		log.Fatal("cengine-storage must run as PID 1")
	}
	if err := boot.MountKernelFilesystems(); err != nil {
		log.Fatalf("mount kernel filesystems: %v", err)
	}
	var verified diskbootstrap.VerifiedBootResult
	err := shutdownStorage(func() error {
		var err error
		verified, err = diskbootstrap.RunVerified("storage")
		if err != nil {
			log.Printf("disk bootstrap: %v", err)
			return err // retained bootFresh survives failed verified evidence
		}
		err = serveStoragePID1(verified)
		log.Printf("storage private boot terminated: %v", err)
		return err
	}, func() error { return verified.Close() }, diskbootstrap.CloseStorageShutdownLeases,
		func() error { return unix.Reboot(unix.LINUX_REBOOT_CMD_POWER_OFF) })
	// Successful poweroff does not return. Any syscall/cleanup uncertainty
	// leaves PID1 alive until the shim's hard fallback. Keep error-carried
	// worker/root owners reachable too; GC must not release their descriptors.
	log.Printf("storage shutdown contained (host fallback required): %v", err)
	for {
		runtime.KeepAlive(verified)
		runtime.KeepAlive(err)
		time.Sleep(time.Hour)
	}
}

func serveStoragePID1(verified diskbootstrap.VerifiedBootResult) error {
	managementAddress, err := boot.KernelParameter("cengine.management_address")
	if err != nil {
		return err
	}
	managementVLAN, err := boot.KernelParameter("cengine.management_vlan")
	if err != nil {
		return err
	}
	vlan, err := strconv.ParseUint(managementVLAN, 10, 16)
	if err != nil {
		return fmt.Errorf("parse management VLAN: %w", err)
	}
	if err := guestnetwork.ConfigureManagement(managementAddress, uint16(vlan)); err != nil {
		return fmt.Errorf("configure management network: %w", err)
	}
	managementIP, _, err := net.ParseCIDR(managementAddress)
	if err != nil {
		return fmt.Errorf("parse management address: %w", err)
	}
	return storageboot.RunLifecycle(context.Background(), verified, managementIP.String())
}
