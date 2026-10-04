package storagefuse

import (
	"strings"
	"testing"
)

func TestPrepareProcessZombieLeaderIdentityIsNotMemberLiveness(t *testing.T) {
	stat := "123 (exited leader) Z " + strings.Repeat("0 ", 18) + "456 0\n"
	if start, ok := prepareProcIdentity(stat, 123, true); !ok || start != 456 {
		t.Fatal("zombie leader identity lost; pidfd decides process liveness", start, ok)
	}
	if _, ok := prepareProcStat(stat, 123); ok {
		t.Fatal("dead requesting thread accepted")
	}
	for _, state := range []string{"X", "x"} {
		if _, ok := prepareProcIdentity(strings.Replace(stat, ") Z ", ") "+state+" ", 1), 123, true); ok {
			t.Fatal("dead owner proc record accepted")
		}
	}
}
