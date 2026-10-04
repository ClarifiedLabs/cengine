package storagemanaged

import (
	"testing"
	"unsafe"

	w "dev.cengine/guest/internal/storagewire"
)

func TestStorageMetadataFrozenLayout(t *testing.T) {
	var a storageAttr
	if unsafe.Sizeof(a) != 80 || storageSessionIOCTL != 0xe5f2 || storageApplyAttrIOCTL != 0x4050e5f3 || w.MetadataMask != 1023 {
		t.Fatal("frozen ABI changed")
	}
	for _, field := range []struct{ got, want uintptr }{
		{unsafe.Offsetof(a.Version), 0}, {unsafe.Offsetof(a.Flags), 4},
		{unsafe.Offsetof(a.FD), 8}, {unsafe.Offsetof(a.Valid), 12},
		{unsafe.Offsetof(a.Semantics), 16}, {unsafe.Offsetof(a.Mode), 24},
		{unsafe.Offsetof(a.UID), 28}, {unsafe.Offsetof(a.GID), 32},
		{unsafe.Offsetof(a.Reserved), 36}, {unsafe.Offsetof(a.Size), 40},
		{unsafe.Offsetof(a.ATime), 48}, {unsafe.Offsetof(a.MTime), 56},
		{unsafe.Offsetof(a.ATimeNsec), 64}, {unsafe.Offsetof(a.MTimeNsec), 68},
		{unsafe.Offsetof(a.Reserved2), 72},
	} {
		if field.got != field.want {
			t.Fatalf("offset %d want %d", field.got, field.want)
		}
	}
}

func TestStorageMetadataExplicitFieldConversion(t *testing.T) {
	// Exercise every typed field individually; this is serialization coverage,
	// not an assertion that a combined chmod/chown/time operation came from FUSE.
	for _, tc := range []struct{ valid, want uint32 }{
		{w.SetMode, 1}, {w.SetUID, 2}, {w.SetGID, 4}, {w.SetSize, 8},
		{w.SetATime, 16}, {w.SetMTime, 32},
		{w.SetATime | w.SetATimeNow, 80}, {w.SetMTime | w.SetMTimeNow, 160},
	} {
		v := w.SetAttrRequest{Valid: tc.valid, Semantics: w.MetadataValid | w.MetadataCTime,
			Mode: 06755, UID: 1001, GID: 1002, Size: 123,
			ATime: w.Timestamp{Seconds: -7, Nanoseconds: 999999999}, MTime: w.Timestamp{Seconds: 42, Nanoseconds: 3}}
		a := metadataAttr(v, 17)
		if a.Version != 1 || a.FD != 17 || a.Valid != tc.want || a.Semantics != uint64(v.Semantics) || a.Flags != 0 || a.Reserved != 0 || a.Reserved2 != [2]uint32{} {
			t.Fatalf("conversion: %+v", a)
		}
		if tc.valid&w.SetMode != 0 {
			if a.Mode != v.Mode {
				t.Fatal(a)
			}
		} else if a.Mode != 0 {
			t.Fatal(a)
		}
		if tc.valid&w.SetUID != 0 {
			if a.UID != v.UID {
				t.Fatal(a)
			}
		} else if a.UID != 0 {
			t.Fatal(a)
		}
		if tc.valid&w.SetGID != 0 {
			if a.GID != v.GID {
				t.Fatal(a)
			}
		} else if a.GID != 0 {
			t.Fatal(a)
		}
		if tc.valid&w.SetSize != 0 {
			if a.Size != int64(v.Size) {
				t.Fatal(a)
			}
		} else if a.Size != 0 {
			t.Fatal(a)
		}
		if tc.valid&w.SetATime != 0 {
			if a.ATime != -7 || a.ATimeNsec != 999999999 {
				t.Fatal(a)
			}
		} else if a.ATime != 0 || a.ATimeNsec != 0 {
			t.Fatal(a)
		}
		if tc.valid&w.SetMTime != 0 {
			if a.MTime != 42 || a.MTimeNsec != 3 {
				t.Fatal(a)
			}
		} else if a.MTime != 0 || a.MTimeNsec != 0 {
			t.Fatal(a)
		}
	}
	for _, semantics := range []w.MetadataSemantics{
		w.MetadataValid | w.MetadataCTime | w.MetadataKillSUID | w.MetadataKillPriv,
		w.MetadataValid | w.MetadataForce | w.MetadataKillSGID,
		w.MetadataValid | w.MetadataTimesSet | w.MetadataTouch | w.MetadataFile | w.MetadataOpen,
	} {
		a := metadataAttr(w.SetAttrRequest{Semantics: semantics}, 8)
		if a.Valid != 0 || a.Semantics != uint64(semantics) {
			t.Fatal("empty intent lost", a)
		}
	}
}
