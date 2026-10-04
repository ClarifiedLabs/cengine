package storagefuse

import (
	"reflect"
	"testing"

	w "dev.cengine/guest/internal/storagewire"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// Linux do_open_execat sets __FMODE_EXEC in file.f_flags. FUSE carries it in
// ordinary OPEN/READ flags, not fuse_open_in.open_flags (go-fuse's Mode field).
func TestExecFlagsNormalizedAtAdapter(t *testing.T) {
	for _, tc := range []struct {
		arch  string
		flags uint32
	}{{"arm64", 0x20020}, {"amd64", 0x8020}} {
		t.Run(tc.arch, func(t *testing.T) {
			if got, ok := openFlags(tc.flags, tc.arch); !ok || got != w.OpenLargeFile {
				t.Fatalf("exec flags: %#x %v", got, ok)
			}
			if got, ok := openFlags(0x20, tc.arch); !ok || got != w.OpenReadOnly {
				t.Fatalf("exec marker escaped into wire flags: %#x %v", got, ok)
			}
			f, fc := fixture()
			f.arch = tc.arch
			status := f.Open(nil, &fuse.OpenIn{InHeader: header(), Flags: tc.flags}, &fuse.OpenOut{})
			wantOpen := w.OpenRequest{Node: 101, Flags: w.OpenLargeFile}
			// The fake server denies valid requests. EACCES, rather than local
			// EINVAL, plus the exact captured request proves adapter dispatch.
			if status != fuse.EACCES || !reflect.DeepEqual(fc.body, wantOpen) || fc.validationErr != nil || fc.aborted != 0 {
				t.Fatalf("OPEN: %v %#v validation=%v aborts=%d", status, fc.body, fc.validationErr, fc.aborted)
			}
			f, fc = fixture()
			f.arch, fc.state = tc.arch, none
			_, status = f.Read(nil, &fuse.ReadIn{InHeader: header(), Fh: 8, Size: 4, Flags: tc.flags}, nil)
			wantRead := w.ReadRequest{Node: 101, Handle: 808, Size: 4, IOFlags: w.OpenLargeFile}
			if status != fuse.EACCES || !reflect.DeepEqual(fc.body, wantRead) || fc.auth != w.OpenGrantAuth || fc.validationErr != nil || fc.aborted != 0 {
				t.Fatalf("READ: %v %#v auth=%v validation=%v aborts=%d", status, fc.body, fc.auth, fc.validationErr, fc.aborted)
			}
		})
	}
}

func TestExecFlagsDoNotRelaxUnknownBits(t *testing.T) {
	for _, arch := range []string{"arm64", "amd64"} {
		for _, unknown := range []uint32{3, 0x10, 0x200000, 0x400000, 0x80000000} {
			flags := uint32(0x20) | unknown
			if _, ok := openFlags(flags, arch); ok {
				t.Fatalf("%s accepted %#x", arch, flags)
			}
			f, fc := fixture()
			f.arch = arch
			if status := f.Open(nil, &fuse.OpenIn{InHeader: header(), Flags: flags}, &fuse.OpenOut{}); status != fuse.EINVAL || fc.body != nil {
				t.Fatalf("%s unknown OPEN dispatched: %v %#v", arch, status, fc.body)
			}
			f, fc = fixture()
			f.arch = arch
			if _, status := f.Read(nil, &fuse.ReadIn{InHeader: header(), Fh: 8, Size: 4, Flags: flags}, nil); status != fuse.EINVAL || fc.body != nil {
				t.Fatalf("%s unknown READ dispatched: %v %#v", arch, status, fc.body)
			}
		}
		f, fc := fixture()
		f.arch = arch
		status := f.Open(nil, &fuse.OpenIn{InHeader: header(), Flags: 0x20, Mode: 1}, &fuse.OpenOut{})
		if status != fuse.EIO || fc.validationErr == nil || fc.aborted != 1 {
			t.Fatalf("%s separate FUSE open flags accepted: %v validation=%v aborts=%d", arch, status, fc.validationErr, fc.aborted)
		}
	}
}
