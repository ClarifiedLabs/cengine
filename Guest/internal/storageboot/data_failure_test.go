package storageboot

import (
	"strings"
	"sync"
	"testing"
)

func TestDataFailureReporterIsBoundedAndOnce(t *testing.T) {
	const line = "cengine storage-data-handshake-failure phase=root-factory category=enotty"
	var r dataFailureReporter
	var mu sync.Mutex
	var got []string
	write := func(p []byte) { mu.Lock(); defer mu.Unlock(); got = append(got, string(p)) }
	for _, bad := range []string{"", "SECRET", line + "\nspoof", line + "\x00", line + strings.Repeat("x", 193)} {
		r.report(bad, write)
	}
	var group sync.WaitGroup
	for i := 0; i < 32; i++ {
		group.Add(1)
		go func() { defer group.Done(); r.report(line, write) }()
	}
	group.Wait()
	if len(got) != 1 || got[0] != line+"\n" {
		t.Fatal("diagnostic was lost, repeated, or accepted unbounded text")
	}
}
