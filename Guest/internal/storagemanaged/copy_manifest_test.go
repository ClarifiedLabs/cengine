package storagemanaged

import (
	"crypto/sha256"
	a "dev.cengine/guest/internal/storageauthority"
	"io"
	"testing"
)

type boundedZeroReader struct {
	left    int64
	maximum int
}

func (r *boundedZeroReader) Read(p []byte) (int, error) {
	if len(p) > r.maximum {
		r.maximum = len(p)
	}
	if r.left == 0 {
		return 0, io.EOF
	}
	n := len(p)
	if int64(n) > r.left {
		n = int(r.left)
	}
	clear(p[:n])
	r.left -= int64(n)
	return n, nil
}
func TestPrepareManifestPreserves64MiBBoundWithStreamingDigest(t *testing.T) {
	if a.MaxCopyManifestBytes != 64<<20 {
		t.Fatal("managed manifest bound regressed")
	}
	for _, n := range []int64{1, 1<<20 + 1, 64 << 20} {
		r := &boundedZeroReader{left: n}
		digest, size, err := digestCopyManifest(r)
		if err != nil || size != uint64(n) {
			t.Fatal(n, size, err)
		}
		if r.maximum > 128<<10 {
			t.Fatal("unbounded read buffer", r.maximum)
		}
		h := sha256.New()
		_, _ = io.CopyBuffer(h, &boundedZeroReader{left: n}, make([]byte, 4096))
		var expected [32]byte
		copy(expected[:], h.Sum(nil))
		if digest != expected {
			t.Fatal("digest mismatch")
		}
	}
	if _, _, err := digestCopyManifest(&boundedZeroReader{left: 64<<20 + 1}); err == nil {
		t.Fatal("oversized manifest accepted")
	}
	if _, _, err := digestCopyManifest(&boundedZeroReader{}); err == nil {
		t.Fatal("empty manifest accepted")
	}
}
