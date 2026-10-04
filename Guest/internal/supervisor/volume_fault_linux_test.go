//go:build linux

package supervisor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"dev.cengine/guest/internal/protocol"
	"golang.org/x/sys/unix"
)

func TestCopyupInterruptionBoundariesRecoverAndRetry(t *testing.T) {
	for _, boundary := range []string{"temporary-manifest", "manifest", "first-entry", "published"} {
		t.Run(boundary, func(t *testing.T) {
			sourcePath, destinationPath := t.TempDir(), t.TempDir()
			for _, name := range []string{"a", "b"} {
				if err := os.WriteFile(filepath.Join(sourcePath, name), []byte(name), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := unix.Chmod(destinationPath, 03750); err != nil {
				t.Fatal(err)
			}
			source, destination := openCopyupTestRoots(t, sourcePath, destinationPath)
			stageConfinedCopyTransaction(t, source, destination, boundary)
			if boundary == "first-entry" {
				entries, err := os.ReadDir(destinationPath)
				if err != nil || len(entries) != 2 { // Journal plus exactly one published entry.
					t.Fatalf("partial publication = %v, %v", entries, err)
				}
			}
			for attempt := 0; attempt < 2; attempt++ {
				if err := recoverConfinedCopyTransaction(destination); err != nil {
					t.Fatal(err)
				}
				assertVolumeRootMetadata(t, destinationPath, uint32(os.Geteuid()), uint32(os.Getegid()), 03750)
				entries, err := os.ReadDir(destinationPath)
				if err != nil || len(entries) != 0 {
					t.Fatalf("recovery %d left partial success: %v, %v", attempt, entries, err)
				}
			}
			if err := copyConfinedDirectory(source, destination); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"a", "b"} {
				if data, err := os.ReadFile(filepath.Join(destinationPath, name)); err != nil || string(data) != name {
					t.Fatalf("retry %s = %q, %v", name, data, err)
				}
			}
		})
	}
}

func TestCopyupPublicationConflictRollsBackEarlierEntries(t *testing.T) {
	sourcePath, destinationPath := t.TempDir(), t.TempDir()
	for _, name := range []string{"a", "z"} {
		if err := os.WriteFile(filepath.Join(sourcePath, name), []byte("image"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(destinationPath, "z"), []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Chmod(destinationPath, 03750); err != nil {
		t.Fatal(err)
	}
	source, destination := openCopyupTestRoots(t, sourcePath, destinationPath)
	err := copyConfinedDirectory(source, destination)
	if !errors.Is(err, unix.EEXIST) || !strings.Contains(err.Error(), `publish copy-up entry "z"`) {
		t.Fatalf("publication error = %v, want wrapped EEXIST", err)
	}
	assertVolumeRootMetadata(t, destinationPath, uint32(os.Geteuid()), uint32(os.Getegid()), 03750)
	entries, err := os.ReadDir(destinationPath)
	if err != nil || len(entries) != 1 || entries[0].Name() != "z" {
		t.Fatalf("failed publication left partial success: %v, %v", entries, err)
	}
	if data, err := os.ReadFile(filepath.Join(destinationPath, "z")); err != nil || string(data) != "keep" {
		t.Fatalf("conflicting entry = %q, %v", data, err)
	}
}

func TestCopyupManifestPublicationFailurePreservesExistingJournal(t *testing.T) {
	path := t.TempDir()
	root, err := openConfinedRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.close()
	metadata, err := confinedRootMetadata(root.fd)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(path, confinedCopyManifestName)
	if err := os.WriteFile(manifestPath, []byte("existing journal"), 0600); err != nil {
		t.Fatal(err)
	}
	err = writeConfinedCopyManifest(root.fd, nil, &metadata)
	if !errors.Is(err, unix.EEXIST) || !strings.Contains(err.Error(), "publish manifest") {
		t.Fatalf("manifest publication = %v, want wrapped EEXIST", err)
	}
	if data, err := os.ReadFile(manifestPath); err != nil || string(data) != "existing journal" {
		t.Fatalf("existing journal = %q, %v", data, err)
	}
	if _, err := os.Lstat(filepath.Join(path, confinedCopyManifestTemporary)); !os.IsNotExist(err) {
		t.Fatalf("failed manifest publication left temporary file: %v", err)
	}
}

func TestCopyupMalformedManifestBlocksInitializationUntilRepaired(t *testing.T) {
	rootfs, destinationPath := t.TempDir(), t.TempDir()
	sourcePath := filepath.Join(rootfs, "data")
	if err := os.Mkdir(sourcePath, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourcePath, "seed"), []byte("image"), 0600); err != nil {
		t.Fatal(err)
	}
	source, destination := openCopyupTestRoots(t, sourcePath, destinationPath)
	publishStaleConfinedCopyTransaction(t, source, destination)
	manifestPath := filepath.Join(destinationPath, confinedCopyTransactionName, confinedCopyManifestName)
	valid, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, []byte(`{"version":`), 0600); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		err := initializeVolumeAt(rootfs, destinationPath, protocol.Mount{Destination: "/data"})
		if err == nil || !strings.Contains(err.Error(), "recover volume copy-up: read stale copy-up transaction") {
			t.Fatalf("initialization accepted damaged journal: %v", err)
		}
		if data, err := os.ReadFile(manifestPath); err != nil || string(data) != `{"version":` {
			t.Fatalf("failed recovery discarded evidence: %q, %v", data, err)
		}
		if data, err := os.ReadFile(filepath.Join(destinationPath, "seed")); err != nil || string(data) != "image" {
			t.Fatalf("failed recovery changed published entry: %q, %v", data, err)
		}
	}
	if err := os.WriteFile(manifestPath, valid, 0600); err != nil {
		t.Fatal(err)
	}
	if err := initializeVolumeAt(rootfs, destinationPath, protocol.Mount{Destination: "/data"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Dir(manifestPath)); !os.IsNotExist(err) {
		t.Fatalf("repaired retry left journal: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(destinationPath, "seed")); err != nil || string(data) != "image" {
		t.Fatalf("repaired retry = %q, %v", data, err)
	}
}

func TestCopyupRootMetadataRecoveryFailureIsNotSuccess(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root: run on the ext4 guest test volume")
	}
	const helper = "CENGINE_TEST_COPYUP_NO_CHOWN"
	if os.Getenv(helper) == "" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCopyupRootMetadataRecoveryFailureIsNotSuccess$")
		command.Env = append(os.Environ(), helper+"=1")
		output, err := command.CombinedOutput()
		if err != nil || !strings.Contains(string(output), "recovery rejected EPERM") {
			t.Fatalf("isolated metadata failure = %v\n%s", err, output)
		}
		return
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires root: run on the ext4 guest test volume")
	}
	sourcePath, destinationPath := t.TempDir(), t.TempDir()
	source, destination := openCopyupTestRoots(t, sourcePath, destinationPath)
	if err := os.Chmod(destinationPath, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(destinationPath, 10003, 10004); err != nil {
		t.Fatal(err)
	}
	publishStaleConfinedCopyTransaction(t, source, destination)
	if err := os.Chown(destinationPath, 10001, 10002); err != nil {
		t.Fatal(err)
	}
	// Capabilities are per-thread; permanently isolate the fault in this child.
	// initializeVolumeAt must execute its recovery inline on this pinned thread.
	runtime.LockOSThread()
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var capabilities [2]unix.CapUserData
	if err := unix.Capget(&header, &capabilities[0]); err != nil {
		t.Fatal(err)
	}
	capabilities[0].Effective &^= 1 << unix.CAP_CHOWN
	if err := unix.Capset(&header, &capabilities[0]); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		err := initializeVolumeAt(sourcePath, destinationPath, protocol.Mount{Destination: "/missing"})
		if !errors.Is(err, unix.EPERM) || !strings.Contains(err.Error(), "restore copy-up root metadata") {
			t.Fatalf("metadata recovery = %v, want wrapped EPERM", err)
		}
		if _, err := os.Stat(filepath.Join(destinationPath, confinedCopyTransactionName, confinedCopyManifestName)); err != nil {
			t.Fatalf("failed restoration discarded journal: %v", err)
		}
		assertVolumeRootMetadata(t, destinationPath, 10001, 10002, 0700)
	}
	fmt.Println("recovery rejected EPERM")
}

func openCopyupTestRoots(t *testing.T, sourcePath, destinationPath string) (*confinedRoot, *confinedRoot) {
	t.Helper()
	source, err := openConfinedRoot(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = source.close() })
	destination, err := openConfinedRoot(destinationPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = destination.close() })
	return source, destination
}
