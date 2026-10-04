//go:build linux && (amd64 || arm64)

package storagemanaged

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

// Exercise actual server cleanup, not the supervisor's syscall fake. Every
// subprocess owns only its supplied ext4 test directory. No mount/VM is created.
func TestCopyCleanupServerCrashWorker(t *testing.T) {
	path, boundary := os.Getenv("CENGINE_COPY_CLEANUP_ROOT"), os.Getenv("CENGINE_COPY_CLEANUP_BOUNDARY")
	if path == "" {
		return
	}
	sealed := strings.HasPrefix(boundary, "sealed/")
	boundary = strings.TrimPrefix(boundary, "sealed/")
	h := copyBootstrapSession(t, path)
	sequence := uint64(0)
	call := func(body w.RequestBody) w.ReplyBody {
		sequence++
		result := copyBootstrapDispatch(t, h, sequence, body)
		if result.Reply.Errno != 0 {
			t.Fatalf("%T: %+v", body, result)
		}
		return result.Reply.Body
	}
	handle := call(w.OpenDirRequest{Node: 1}).(w.OpenDirReply).Opened.Handle
	control := func(action w.PrepareAction, id a.ID) w.PrepareReply {
		return call(w.PrepareRequest{Node: 1, Handle: handle, Action: action, Intent: id}).(w.PrepareReply)
	}
	intent := control(w.BeginCopy, "").Intent
	intent = control(w.BindCopyTransaction, intent.ID).Intent
	transaction := filepath.Join(path, "volumes", "data", copyTransactionPath)
	copyHostMust(t, os.Mkdir(filepath.Join(transaction, "staging"), 0700))
	copyHostMust(t, os.WriteFile(filepath.Join(transaction, "staging", "child"), []byte("unsealed-private"), 0600))
	manifest := []byte("present but deliberately unsealed")
	if sealed {
		identity, err := copyIdentityAt(int(h.session.root.Fd()), copyTransactionPath+"/staging/child")
		copyHostMust(t, err)
		manifest, err = json.Marshal(map[string]any{
			"version": 4, "intent": intent.ID, "physical": intent.Root,
			"entries": []map[string]any{{"path": "child", "identity": identity}},
		})
		copyHostMust(t, err)
	}
	copyHostMust(t, os.WriteFile(filepath.Join(transaction, "manifest.json"), manifest, 0600))
	if sealed {
		copyHostMust(t, unix.Syncfs(int(h.session.root.Fd())))
		intent = control(w.SealManifest, intent.ID).Intent
		if intent.Phase != a.CopySealed {
			t.Fatal("server did not seal exact manifest")
		}
	}
	copyHostMust(t, unix.Fchmod(int(h.session.root.Fd()), 0750))
	copyHostMust(t, unix.UtimesNanoAt(int(h.session.root.Fd()), "", []unix.Timespec{{Sec: 123456789, Nsec: 123456789}, {Sec: 234567890, Nsec: 987654321}}, unix.AT_EMPTY_PATH))
	intent = control(w.StartCleanup, intent.ID).Intent
	expected, err := json.Marshal(intent.Cleanup)
	copyHostMust(t, err)
	copyHostMust(t, os.WriteFile(filepath.Join(path, "cleanup-expected.json"), expected, 0600))
	// Finish visits child, staging and manifest in that order, then removes the
	// transaction. Its final syncfs follows exact root timestamp restoration.
	syncs := 0
	h.session.registry.syncOps.fsync = func(fd int) error {
		syncs++
		if boundary == "after-child-unlink" && syncs == 1 {
			os.Exit(74)
		}
		if err := unix.Fsync(fd); err != nil {
			return err
		}
		if boundary == "after-manifest-sync" && syncs == 3 {
			os.Exit(74)
		}
		return nil
	}
	h.session.registry.copyCleanupCheckpoint = func(step string) error {
		if boundary == "after-transaction-unlink" && step == "transaction-removed-before-root-restore" {
			os.Exit(74)
		}
		return nil
	}
	h.session.registry.syncOps.syncfs = func(fd int) error {
		if err := unix.Syncfs(fd); err != nil {
			return err
		}
		if boundary == "after-root-sync" {
			os.Exit(74)
		}
		return nil
	}
	if boundary == "after-finish-before-reply" {
		h.session.registry.prepareOperation = func(g *a.Guard, request w.PrepareRequest) (w.ReplyBody, error) {
			_, err := h.session.prepare(g, request)
			copyHostMust(t, err)
			os.Exit(74)
			return nil, nil
		}
	}
	control(w.FinishCopy, intent.ID)
	t.Fatal("server cleanup fault boundary not reached")
}

func TestCopyCleanupServerCrashRestoresExactRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires Linux root with storageidentity setup capabilities")
	}
	for _, boundary := range []string{"after-child-unlink", "after-manifest-sync", "after-transaction-unlink", "after-root-sync", "after-finish-before-reply", "sealed/after-child-unlink", "sealed/after-manifest-sync", "sealed/after-transaction-unlink", "sealed/after-root-sync", "sealed/after-finish-before-reply"} {
		t.Run(boundary, func(t *testing.T) {
			path := t.TempDir()
			var fs unix.Statfs_t
			copyHostMust(t, unix.Statfs(path, &fs))
			if fs.Type != unix.EXT4_SUPER_MAGIC {
				t.Fatal("TMPDIR must be real ext4")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCopyCleanupServerCrashWorker$", "-test.count=1")
			cmd.Env = append(os.Environ(), "CENGINE_COPY_CLEANUP_ROOT="+path, "CENGINE_COPY_CLEANUP_BOUNDARY="+boundary, "GORACE=atexit_sleep_ms=0")
			out, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 74 {
				t.Fatalf("worker: %v\n%s", err, out)
			}
			raw, err := os.ReadFile(filepath.Join(path, "cleanup-expected.json"))
			copyHostMust(t, err)
			var expected a.CopyCleanupV1
			copyHostMust(t, json.Unmarshal(raw, &expected))
			h := copyBootstrapSession(t, path)
			opened := copyBootstrapDispatch(t, h, 1, w.OpenDirRequest{Node: 1})
			if opened.Reply.Errno != 0 {
				t.Fatal(opened)
			}
			handle := opened.Reply.Body.(w.OpenDirReply).Opened.Handle
			begun := copyBootstrapDispatch(t, h, 2, w.PrepareRequest{Node: 1, Handle: handle, Action: w.BeginCopy})
			if begun.Reply.Errno != 0 {
				t.Fatal(begun)
			}
			intent := begun.Reply.Body.(w.PrepareReply).Intent
			if strings.TrimPrefix(boundary, "sealed/") != "after-finish-before-reply" && intent.Phase != a.CopyCleaning {
				t.Fatalf("lost durable cleanup: %+v", intent)
			}
			finished := copyBootstrapDispatch(t, h, 3, w.PrepareRequest{Node: 1, Handle: handle, Action: w.FinishCopy, Intent: intent.ID})
			if finished.Reply.Errno != 0 {
				t.Fatal(finished)
			}
			copyHostMust(t, h.guard.CheckCopyReplay())
			got, err := copyRootCleanup(int(h.session.root.Fd()))
			copyHostMust(t, err)
			expected.Manifest, expected.Staging = a.Ext4ObjectV1{}, a.Ext4ObjectV1{}
			if got != expected {
				t.Fatalf("cleanup lost exact root metadata: got %+v want %+v", got, expected)
			}
			if _, err := os.Lstat(filepath.Join(path, "volumes", "data", copyTransactionPath)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("cleanup retained transaction", err)
			}
		})
	}
}
