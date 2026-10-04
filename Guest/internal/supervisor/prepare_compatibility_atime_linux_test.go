//go:build linux

package supervisor

import (
	"os"
	"path/filepath"
	"testing"

	"dev.cengine/guest/internal/preparecompat"
	"golang.org/x/sys/unix"
)

// Source evidence uses only stat operations. These tests are compile-only in the
// source carrier verification; they do not claim a VM checkpoint or persistence.
func compatibilitySourceFixture(t *testing.T) (string, *confinedRoot) {
	t.Helper()
	directory := t.TempDir()
	for _, name := range []string{"a", "z"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(name), 0600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := openConfinedRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.close() })
	return directory, root
}
func setCompatibilitySourceAtimes(t *testing.T, root *confinedRoot, times preparecompat.SourceAtimes) {
	t.Helper()
	for name, value := range map[string]uint64{"": times.Root, "a": times.A, "z": times.Z} {
		flags := unix.AT_SYMLINK_NOFOLLOW
		if name == "" {
			flags = unix.AT_EMPTY_PATH
		}
		atime := unix.NsecToTimespec(int64(value))
		if err := unix.UtimesNanoAt(root.fd, name, []unix.Timespec{atime, {Sec: 1_700_000_000, Nsec: 987}}, flags); err != nil {
			t.Fatal(err)
		}
	}
}
func captureCompatibilitySourceAtimes(t *testing.T, root *confinedRoot) preparecompat.SourceAtimes {
	t.Helper()
	// Zero witness gates only a read-only predicate here. No authority, DATA,
	// physical publication, or callable-copy test seam is fabricated.
	copy := &managedCopy{compatibility: &preparecompat.Witness{}}
	if err := copy.compatibilitySource(root); err != nil || copy.sourceAtimes == nil {
		t.Fatal("source snapshot", err)
	}
	return *copy.sourceAtimes
}
func TestPrepareCompatibilitySourcePreflightPreservesAtime(t *testing.T) {
	directory, root := compatibilitySourceFixture(t)
	expected := preparecompat.SourceAtimes{Root: 123456789000000123, A: 123456790000000234, Z: 123456791000000345}
	setCompatibilitySourceAtimes(t, root, expected)
	if got := captureCompatibilitySourceAtimes(t, root); got != expected {
		t.Fatalf("snapshot=%v want=%v", got, expected)
	}
	if got := captureCompatibilitySourceAtimes(t, root); got != expected {
		t.Fatalf("stat-only capture changed atime: %v", got)
	}
	// Extra-entry detection is deliberately deferred to the real authenticated
	// manifest; stat-only evidence capture must not enumerate the source.
	if err := os.WriteFile(filepath.Join(directory, "extra"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	copy := &managedCopy{compatibility: &preparecompat.Witness{}}
	if err := copy.compatibilitySource(root); err != nil {
		t.Fatal("stat-only snapshot", err)
	}
	if err := os.Remove(filepath.Join(directory, "z")); err != nil {
		t.Fatal(err)
	}
	if copy.compatibilitySource(root) == nil || copy.sourceAtimes != nil {
		t.Fatal("missing z retained a stale snapshot")
	}
	if err := os.Symlink("a", filepath.Join(directory, "z")); err != nil {
		t.Fatal(err)
	}
	if copy.compatibilitySource(root) == nil {
		t.Fatal("symlink source accepted")
	}
}
func TestPrepareCompatibilityFreshCopyUsesCurrentRetainedSourceAtimes(t *testing.T) {
	_, source := compatibilitySourceFixture(t)
	first := preparecompat.SourceAtimes{Root: 1_600_000_000_000_000_101, A: 1_600_000_001_000_000_202, Z: 1_600_000_002_000_000_303}
	setCompatibilitySourceAtimes(t, source, first)
	firstDestination, err := openConfinedRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer firstDestination.close()
	firstSnapshot := captureCompatibilitySourceAtimes(t, source)
	if err := copyConfinedDirectory(source, firstDestination); err != nil {
		t.Fatal("first real copy", err)
	}
	if got := captureCompatibilitySourceAtimes(t, firstDestination); got != firstSnapshot {
		t.Fatalf("first output=%v want snapshot=%v", got, firstSnapshot)
	}
	// Retained image source atimes can advance while old destination timestamps
	// remain unchanged. Set a deterministic later fixture state without depending
	// on mount-specific relatime/noatime policy or sleep as evidence of a read.
	later := preparecompat.SourceAtimes{Root: 1_800_000_000_000_000_404, A: 1_800_000_001_000_000_505, Z: 1_800_000_002_000_000_606}
	setCompatibilitySourceAtimes(t, source, later)
	freshSnapshot := captureCompatibilitySourceAtimes(t, source)
	if freshSnapshot == firstSnapshot || freshSnapshot != later {
		t.Fatal("fresh attempt reused old destination atimes")
	}
	freshDestination, err := openConfinedRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer freshDestination.close()
	if err := copyConfinedDirectory(source, freshDestination); err != nil {
		t.Fatal("fresh real copy", err)
	}
	if got := captureCompatibilitySourceAtimes(t, freshDestination); got != freshSnapshot {
		t.Fatalf("fresh output=%v want current source=%v", got, freshSnapshot)
	}
	if got := captureCompatibilitySourceAtimes(t, firstDestination); got != firstSnapshot {
		t.Fatal("old destination unexpectedly changed")
	}
}
func TestPrepareCompatibilitySourceAtimeConversionBounds(t *testing.T) {
	const max = uint64(1<<63 - 1)
	for _, value := range []uint64{0, 1, max} {
		got, err := sourceAtimeNanos(unix.NsecToTimespec(int64(value)))
		if err != nil || got != value {
			t.Fatalf("timestamp %d => %d,%v", value, got, err)
		}
	}
	for _, value := range []unix.Timespec{{Sec: -1}, {Nsec: -1}, {Nsec: 1_000_000_000}, {Sec: 9_223_372_036, Nsec: 854_775_808}, {Sec: 9_223_372_037}} {
		if _, err := sourceAtimeNanos(value); err == nil {
			t.Fatal("invalid timestamp accepted", value)
		}
	}
}
