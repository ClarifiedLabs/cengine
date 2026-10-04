package storagefuse

import "testing"

func TestMountBindingNeverAdoptsReplacementOrPartialSetup(t *testing.T) {
	before := "21 1 0:1 / / rw - rootfs rootfs rw\n"
	own := "22 21 0:83 / /private/mnt rw - fuse.managed-v3 managed-v3 rw\n"
	replacement := "23 21 0:84 / /private/mnt rw - fuse.managed-v3 managed-v3 rw\n"
	for _, tc := range []struct {
		name, before, after string
		descriptor          uint64
		ok                  bool
	}{
		{"new", before, before + own, 22, true},
		{"replacement-descriptor", before, before + replacement, 22, false},
		{"existing-ID", before + own, before + own, 22, false},
		{"existing-connection", before + "20 21 0:83 / /other rw - fuse.managed-v3 managed-v3 rw\n", before + own, 22, false},
		{"stacked", before, before + own + replacement, 22, false},
		{"missing-descriptor", before, before + own, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id, conn, err := bindNewMount(tc.before, tc.after, "/private/mnt", tc.descriptor)
			if (err == nil) != tc.ok {
				t.Fatal(id, conn, err)
			}
			if err != nil && (id != 0 || conn != 0) {
				t.Fatal("failed binding retained authority")
			}
		})
	}
	for _, tc := range []struct {
		info     string
		id, conn uint64
		ok       bool
	}{
		{before + own, 22, 83, true}, {before + own, 0, 0, false},
		{before + replacement, 22, 83, false}, {before + own + replacement, 22, 83, false},
		{before + own, 22, 84, false}, {before + own, 23, 83, false},
	} {
		if matchesMount(tc.info, "/private/mnt", tc.id, tc.conn) != tc.ok {
			t.Fatal(tc)
		}
	}
}
func TestDescriptorMountIDRequiresOneNonzeroID(t *testing.T) {
	id, err := parseDescriptorMountID("pos:\t0\nflags:\t012000000\nmnt_id:\t42\nino:\t1\n")
	if err != nil || id != 42 {
		t.Fatal(id, err)
	}
	for _, info := range []string{"", "mnt_id: 0", "mnt_id: -1", "mnt_id: 1\nmnt_id: 2", "mnt_id: x", "mnt_id: 1 extra"} {
		if id, err := parseDescriptorMountID(info); err == nil || id != 0 {
			t.Fatal(info, id, err)
		}
	}
}
