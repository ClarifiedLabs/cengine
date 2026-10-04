package storageserver

import (
	a "dev.cengine/guest/internal/storageauthority"
	"testing"
)

func TestResourcesCannotBackMultipleServers(t *testing.T) {
	f := newFixture(t, Limits{}, false)
	if !f.s.resources.Idle() {
		t.Fatal("new resources not idle")
	}
	if _, err := NewWithResources(f.s.resources, Config{TLSConfig: f.inputTLS, ClientRoots: [][]byte{f.ca.Raw}, RequestRetirement: func(a.DataHello, error) {}}); err == nil {
		t.Fatal("resource owner reused")
	}
}
