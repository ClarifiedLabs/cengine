//go:build linux && (amd64 || arm64)

package storagemanaged

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	"dev.cengine/guest/internal/storageauthoritytest"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

const managedCrashExit = 92

type managedCrashManifest struct {
	Lifecycle storageauthoritytest.Fixture
	Bootstrap ed25519.PublicKey
	Before    a.Snapshot
	Stable    a.Receipt
}

// This is the real Linux managed dispatcher, authority journal and filesystem,
// not a simulated authority principal. Fault hooks are private to this process.
// It needs the same experimental kernel/ext4/capabilities as the package suite.
func TestManagedDurabilityCrashWorker(t *testing.T) {
	if os.Getenv("CENGINE_MANAGED_IO_WORKER") != "1" {
		return
	}
	f := newFixtureAt(t, os.Getenv("CENGINE_MANAGED_IO_ROOT"))
	s, root := f.session(a.ReadWrite)
	stableBinding, _ := f.principal(a.ReadOnly)
	stable, err := f.authority.Retire(t.Context(), f.control, a.RetireRequest{Operation: newID(t), Store: f.storeID, Volume: f.volumeID, Attachment: stableBinding.Attachment, Launch: stableBinding.Launch})
	must(t, err)
	c := f.call(s, caller(1001, 1001), w.CreateRequest{Parent: root.Node, Name: []byte("payload"), Flags: w.OpenReadWrite, Mode: 0600}).(w.CreateReply)
	f.call(s, grantAuth, w.WriteRequest{Node: c.Entry.Node, Handle: c.Opened.Handle, Data: []byte("external-ACK-prefix\n")})
	before, err := f.authority.Query(f.control)
	must(t, err)
	data, err := json.Marshal(managedCrashManifest{Lifecycle: *f.lifecycle, Bootstrap: f.bootstrap, Before: before, Stable: stable})
	must(t, err)
	fmt.Printf("ACK:prefix:%s\n", data)
	kind := os.Getenv("CENGINE_MANAGED_IO_KIND")
	faultName := os.Getenv("CENGINE_MANAGED_IO_FAULT")
	fault := error(unix.EIO)
	if faultName == "enospc" {
		fault = unix.ENOSPC
	}
	fail := func() error {
		fmt.Printf("FAULT:%s\n", fault)
		if faultName == "crash" {
			os.Exit(managedCrashExit)
		}
		return fault
	}
	var body w.RequestBody
	auth := grantAuth
	switch kind {
	case "rejected":
		auth = caller(^uint32(0), 1001) // wire-valid; Worker rejects before callback entry
		body = w.FsyncRequest{Node: c.Entry.Node, Handle: c.Opened.Handle}
	case "panic", "goexit":
		auth = caller(1001, 1001)
		f.registry.syncOps.fsync = func(int) error {
			if kind == "goexit" {
				runtime.Goexit()
			}
			panic("injected caller-worker termination")
		}
		body = w.FsyncRequest{Node: c.Entry.Node, Handle: c.Opened.Handle}
	case "fsync":
		f.registry.syncOps.fsync = func(int) error { return fail() }
		body = w.FsyncRequest{Node: c.Entry.Node, Handle: c.Opened.Handle}
	case "syncfs":
		f.registry.syncOps.syncfs = func(int) error { return fail() }
		body = w.WriteRequest{Node: c.Entry.Node, Handle: c.Opened.Handle, Offset: uint64(len("external-ACK-prefix\n")), Data: []byte("unacknowledged-suffix\n")}
	case "namespace":
		f.registry.postNamespace = fail
		auth = caller(1001, 1001)
		body = w.MkdirRequest{Parent: root.Node, Name: []byte("new-directory"), Mode: 0700}
	case "metadata":
		f.registry.syncOps.syncfs = func(int) error { return fail() }
		auth = caller(1001, 1001)
		body = w.SetXAttrRequest{Node: c.Entry.Node, Name: []byte("user.obligation"), Value: []byte("metadata")}
	case "success":
		body = w.FsyncRequest{Node: c.Entry.Node, Handle: c.Opened.Handle}
	default:
		t.Fatal("bad kind", kind)
	}
	result, err := dispatchRaw(f, s, auth, body)
	if kind == "rejected" {
		must(t, err)
		if result.Reply.Errno != uint32(unix.EINVAL) {
			t.Fatal(result)
		}
		_, err = f.authority.Query(f.control)
		must(t, err)
		fmt.Println("ACK:completed") // completed rejection, not a filesystem mutation
	} else if kind == "success" {
		must(t, err)
		if result.Reply.Errno != 0 {
			t.Fatal(result)
		}
		fmt.Println("ACK:completed")
	} else if !errors.Is(err, ErrVolumeFault) || (kind != "panic" && kind != "goexit" && !errors.Is(err, fault)) {
		t.Fatalf("fault not latched: %v", err)
	}
	// No retire or cleanup is allowed to create the evidence this test relies on.
	os.Exit(managedCrashExit)
}

func TestManagedDurabilityFaultCrashFencesRestart(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires Linux root with storageidentity setup capabilities")
	}
	for _, kind := range []string{"fsync", "syncfs", "namespace", "metadata", "panic", "goexit", "rejected", "success"} {
		faults := []string{"eio", "enospc", "crash"}
		if kind == "success" || kind == "panic" || kind == "goexit" || kind == "rejected" {
			faults = []string{"none"}
		}
		for _, fault := range faults {
			t.Run(kind+"/"+fault, func(t *testing.T) {
				path := t.TempDir()
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestManagedDurabilityCrashWorker$", "-test.count=1")
				cmd.Env = append(os.Environ(), "CENGINE_MANAGED_IO_WORKER=1", "CENGINE_MANAGED_IO_ROOT="+path, "CENGINE_MANAGED_IO_KIND="+kind, "CENGINE_MANAGED_IO_FAULT="+fault, "GORACE=atexit_sleep_ms=0")
				output, err := cmd.CombinedOutput()
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != managedCrashExit {
					t.Fatalf("worker: %v\n%s", err, output)
				}
				var m managedCrashManifest
				for _, line := range strings.Split(string(output), "\n") {
					if strings.HasPrefix(line, "ACK:prefix:") {
						must(t, json.Unmarshal([]byte(strings.TrimPrefix(line, "ACK:prefix:")), &m))
					}
				}
				if m.Stable.Revision == 0 {
					t.Fatalf("missing external ACK: %s", output)
				}
				payload, err := os.ReadFile(filepath.Join(path, "volumes", "data", "payload"))
				must(t, err)
				if !bytes.HasPrefix(payload, []byte("external-ACK-prefix\n")) {
					t.Fatal("lost externally acknowledged prefix")
				}
				raw, err := os.ReadFile(filepath.Join(path, ".cengine-storage-authority", "state.json"))
				must(t, err)
				var state a.Snapshot
				must(t, json.Unmarshal(raw, &state))
				old := state.Attachments[m.Stable.Attachment].Receipt
				if old == nil || *old != m.Stable {
					t.Fatal("old receipt changed")
				}
				for id, rec := range state.Attachments {
					if m.Before.Attachments[id].Receipt == nil && rec.Receipt != nil {
						t.Fatal("fault manufactured receipt")
					}
				}
				root, err := os.Open(path)
				must(t, err)
				defer root.Close()
				registry, err := NewRegistry(new(sync.Mutex))
				must(t, err)
				authority, err := m.Lifecycle.Open(a.Config{Root: root, DeviceID: "isolated-ext4-test", BootstrapKey: m.Bootstrap, Barrier: registry.Barrier})
				if kind != "success" && kind != "rejected" {
					if authority != nil {
						_ = authority.Close()
						t.Fatal("faulting data operation reopened")
					}
					if !errors.Is(err, a.ErrRepairRequired) {
						t.Fatal(err)
					}
					return
				}
				must(t, err)
				must(t, authority.Close())
				if !bytes.Contains(output, []byte("ACK:completed\n")) {
					t.Fatal("missing success ACK")
				}
			})
		}
	}
}
