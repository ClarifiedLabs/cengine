//go:build linux

package supervisor

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	w "dev.cengine/guest/internal/storagewire"
	"golang.org/x/sys/unix"
)

func TestManagedV4UnexpectedPrivateEntryAuthorityRefusalRetainsWholeTransaction(t *testing.T) {
	for _, name := range []string{"staging/zz-late", "manifest.tmp", "unexpected"} {
		t.Run(name, func(t *testing.T) {
			f := newManagedCopyFixture(t)
			f.journal(t)
			relative := filepath.Join(confinedCopyTransactionName, name)
			managedCleanupMust(t, os.WriteFile(filepath.Join(f.base, relative), []byte("not-in-sealed-manifest"), 0600))
			// Real private preflight belongs to storagemanaged. Here an explicit
			// authority refusal must propagate, without supervisor deletion/probes.
			refusal := errors.Join(errors.New("authority refused unexpected private entry"), unix.ESTALE)
			f.failure[w.RollbackCopy] = refusal
			assertManagedRollbackDelegation(t, f, f.copy.intent, refusal, relative)
		})
	}
}
