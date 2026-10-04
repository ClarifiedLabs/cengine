//go:build linux

package diskbootstrap

import "testing"

func TestStorageShutdownDistinguishesEarlyFailureFromUnleasedMount(t *testing.T) {
	bootMu.Lock()
	oldFresh, oldProbe, oldUnleased := bootFresh, bootProbe, bootStorageUnleasedMount
	bootFresh, bootProbe, bootStorageUnleasedMount = nil, nil, false
	bootMu.Unlock()
	t.Cleanup(func() {
		bootMu.Lock()
		bootFresh, bootProbe, bootStorageUnleasedMount = oldFresh, oldProbe, oldUnleased
		bootMu.Unlock()
	})
	if err := CloseStorageShutdownLeases(); err != nil {
		t.Fatal("early fatal boot has no dirty mount", err)
	}
	bootMu.Lock()
	bootStorageUnleasedMount = true
	bootMu.Unlock()
	if err := CloseStorageShutdownLeases(); err == nil {
		t.Fatal("ordinary mount claimed clean shutdown without lease")
	}
}
