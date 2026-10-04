//go:build linux

package supervisor

import (
	"reflect"

	"dev.cengine/guest/internal/preparecompat"
	"golang.org/x/sys/unix"
)

func (copy *managedCopy) compatibilityRootSynced(m managedCopyManifest, expected confinedCopyRootMetadata, times unix.Stat_t) error {
	if copy.compatibility == nil || copy.compatibility.Arm().CaseName != "vm-root-synced-before-cleanup" {
		return nil
	}
	if copy.sourceAtimes == nil || copy.compatibilityManifest(m) != nil {
		return preparecompat.ErrInvalidFrame
	}
	// Compare final source metadata, not the manifest's saved pre-copy root.
	actual, err := confinedRootMetadata(copy.root.fd)
	var st unix.Stat_t
	if err != nil || unix.Fstat(copy.root.fd, &st) != nil || actual.UID != expected.UID || actual.GID != expected.GID || actual.Mode != expected.Mode || !reflect.DeepEqual(actual.Xattrs, expected.Xattrs) || st.Atim != times.Atim || st.Mtim != times.Mtim {
		return preparecompat.ErrInvalidFrame
	}
	root, e1 := copy.identity("")
	transaction, e2 := copy.identity(confinedCopyTransactionName)
	published, e3 := copy.identity("a")
	last, e4 := copy.identity("z")
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
		return preparecompat.ErrInvalidFrame
	}
	for _, e := range m.Entries {
		if e.Path == "a" && e.Identity != published || e.Path == "z" && e.Identity != last {
			return preparecompat.ErrInvalidFrame
		}
	}
	// For this explicit stage, staged identifies the sealed z object now in the
	// public root, not a remaining staging entry. Stage is mandatory on all peers.
	o, err := copy.compatibility.Observation(copy.intent, root, transaction, published, last, *copy.sourceAtimes)
	if err != nil {
		return err
	}
	return copy.compatibility.PublishAndHold(o)
}
