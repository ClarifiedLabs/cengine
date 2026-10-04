package supervisor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestFinalizeConfinedCopyPreservesRootTimeAfterJournalRemoval(t *testing.T) {
	root := t.TempDir()
	journal := filepath.Join(root, ".cengine-copyup-transaction")
	if err := os.Mkdir(journal, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(journal, "manifest.json"), []byte("journal"), 0600); err != nil {
		t.Fatal(err)
	}
	fd, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer fd.Close()
	atime, mtime := time.Unix(1_600_000_000, 321_000_000), time.Unix(1_700_000_000, 123_000_000)
	// Exercise real namespace cleanup, timestamp updates and directory fsync in
	// the production finalizer on every host. Linux tests also cover its caller.
	if err := finalizeConfinedCopy(
		func() error { return os.Chtimes(root, atime, mtime) },
		fd.Sync,
		func() error { return os.RemoveAll(journal) },
		func(err error) error { return err },
	); err != nil {
		t.Fatal(err)
	}
	stat, err := fd.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if !stat.ModTime().Equal(mtime) {
		t.Fatalf("root mtime after journal cleanup = %v, want %v", stat.ModTime(), mtime)
	}
	if _, err := os.Stat(journal); !os.IsNotExist(err) {
		t.Fatalf("journal remains: %v", err)
	}
}

func TestFinalizeConfinedCopyOrderingAndFailures(t *testing.T) {
	wantOrder := []string{"times-1", "sync-1", "remove", "times-2", "sync-2"}
	for failure := -1; failure < len(wantOrder); failure++ {
		t.Run(fmt.Sprint(failure), func(t *testing.T) {
			var calls []string
			failureErr := errors.New("injected failure")
			step := func(name string) error {
				calls = append(calls, name)
				if len(calls)-1 == failure {
					return failureErr
				}
				return nil
			}
			timesCalls, syncCalls, rollbacks := 0, 0, 0
			err := finalizeConfinedCopy(
				func() error { timesCalls++; return step(fmt.Sprintf("times-%d", timesCalls)) },
				func() error { syncCalls++; return step(fmt.Sprintf("sync-%d", syncCalls)) },
				func() error { return step("remove") },
				func(err error) error { rollbacks++; return err },
			)
			want := wantOrder
			if failure >= 0 {
				want = want[:failure+1]
				if !errors.Is(err, failureErr) {
					t.Fatalf("error = %v, want injected error", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(calls, want) {
				t.Fatalf("operations = %v, want %v", calls, want)
			}
			wantRollbacks := 0
			if failure == 0 || failure == 1 {
				wantRollbacks = 1
			}
			if rollbacks != wantRollbacks {
				t.Fatalf("rollbacks = %d, want %d (journal must survive until preflight and sync)", rollbacks, wantRollbacks)
			}
		})
	}
}
