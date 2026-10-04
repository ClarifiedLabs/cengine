package storagefuse

import (
	"testing"

	c "dev.cengine/guest/internal/storageclient"
	w "dev.cengine/guest/internal/storagewire"
	"github.com/hanwen/go-fuse/v2/fuse"
)

func TestLocalPolicyErrorsAndUnknownFlags(t *testing.T) {
	h := header()
	for _, tc := range []struct {
		err  error
		want fuse.Status
	}{{w.ErrReadOnly, fuse.EROFS}, {c.ErrCapacity, fuse.EAGAIN}} {
		f, fc := fixture()
		fc.errorDo = tc.err
		if got := f.Open(nil, &fuse.OpenIn{InHeader: h, Flags: 2}, &fuse.OpenOut{}); got != tc.want || fc.aborted != 0 {
			t.Fatal(got, fc.aborted)
		}
	}
	f, fc := fixture()
	if got := f.Open(nil, &fuse.OpenIn{InHeader: h, Flags: 1 << 31}, &fuse.OpenOut{}); got != fuse.EINVAL || fc.body != nil || len(fc.captured) != 1 {
		t.Fatal(got, fc)
	}
	f, fc = fixture()
	fc.state = none
	fc.errorDo = c.ErrCapacity
	f.Release(nil, &fuse.ReleaseIn{InHeader: h, Fh: 8})
	if fc.aborted != 1 {
		t.Fatal("cleanup failure must abort")
	}
	f, fc = fixture()
	fc.result = &c.Result{Reply: w.Reply{Errno: 4096}}
	if got := f.Lookup(nil, &h, "x", &fuse.EntryOut{}); got != fuse.EIO || fc.aborted != 1 {
		t.Fatal(got, fc)
	}
}
