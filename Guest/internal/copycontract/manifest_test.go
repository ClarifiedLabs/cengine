package copycontract

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"dev.cengine/guest/internal/storageauthority"
	"golang.org/x/sys/unix"
)

func object(inode, generation, kind uint32) storageauthority.Ext4ObjectV1 {
	v := storageauthority.Ext4ObjectV1{Inode: uint64(inode), Generation: generation, FileType: kind, HandleType: 1, HandleSize: 8}
	binary.LittleEndian.PutUint32(v.Handle[:4], inode)
	binary.LittleEndian.PutUint32(v.Handle[4:], generation)
	return v
}

func validManifest() Manifest {
	return Manifest{
		Version: 4, Intent: "00000000-0000-4000-8000-000000000001",
		Physical: storageauthority.CopyRootV1{Store: "store", Volume: "volume", BackingUUID: [16]byte{1}, Root: object(2, 3, unix.S_IFDIR)},
		Root: &RootMetadata{Filesystem: [2]int32{1, -2}, Device: 3, Inode: 4, UID: 5, GID: 6, Mode: 7,
			Xattrs: &XattrSnapshot{State: "supported", Entries: []Xattr{{Name: "user.\xff", Value: []byte{0, 255}}, {Name: "user.empty", Value: []byte{}}}}},
		Entries: []Entry{{Path: "file", Identity: object(4, 5, unix.S_IFREG)}},
	}
}

func marshal(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestExactJSON(t *testing.T) {
	m := validManifest()
	const root = `{"filesystem":[1,-2],"device":3,"inode":4,"uid":5,"gid":6,"mode":7,"xattrs":{"state":"supported","entries":[{"name":"dXNlci7/","value":"AP8="},{"name":"dXNlci5lbXB0eQ==","value":""}]}}`
	const physical = `{"Store":"store","Volume":"volume","BackingUUID":[1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"Root":{"Inode":2,"Generation":3,"FileType":16384,"HandleType":1,"HandleSize":8,"Handle":[2,0,0,0,3,0,0,0]}}`
	const entries = `[{"path":"file","identity":{"Inode":4,"Generation":5,"FileType":32768,"HandleType":1,"HandleSize":8,"Handle":[4,0,0,0,5,0,0,0]}}]`
	want := `{"version":4,"intent":"00000000-0000-4000-8000-000000000001","physical":` + physical + `,"root":` + root + `,"entries":` + entries + `}`
	raw := marshal(t, m)
	if string(raw) != want {
		t.Fatalf("JSON = %s\nwant = %s", raw, want)
	}
	decoded, err := DecodeManifest(append(raw, '\n'))
	if err != nil || !reflect.DeepEqual(decoded, m) {
		t.Fatalf("roundtrip = %+v, %v", decoded, err)
	}
	m.Root.Xattrs = nil
	if got := string(marshal(t, m.Root)); got != `{"filesystem":[1,-2],"device":3,"inode":4,"uid":5,"gid":6,"mode":7}` {
		t.Fatalf("legacy root = %s", got)
	}
	m.Root = nil
	if got := string(marshal(t, m)); got != `{"version":4,"intent":"00000000-0000-4000-8000-000000000001","physical":`+physical+`,"root":null,"entries":`+entries+`}` {
		t.Fatalf("nil root = %s", got)
	}
}

func TestDecodeManifestStrictSchema(t *testing.T) {
	m := validManifest()
	raw := string(marshal(t, m))
	rootJSON, xattrsJSON := string(marshal(t, m.Root)), string(marshal(t, m.Root.Xattrs))
	cases := map[string]string{
		"empty": "", "null": "null", "array": "[]",
		"unknown":          strings.Replace(raw, `"version":4`, `"unknown":0,"version":4`, 1),
		"unknown-root":     strings.Replace(raw, `"filesystem":`, `"extra":0,"filesystem":`, 1),
		"unknown-identity": strings.Replace(raw, `"Inode":2`, `"extra":0,"Inode":2`, 1),
		"unknown-xattr":    strings.Replace(raw, `"state":`, `"extra":0,"state":`, 1),
		"trailing-object":  raw + `{}`, "trailing-null": raw + `null`, "trailing-garbage": raw + `!`,
		"legacy-version": strings.Replace(raw, `"version":4`, `"version":3`, 1),
		"future-version": strings.Replace(raw, `"version":4`, `"version":5`, 1),
		"missing-root":   strings.Replace(raw, `"root":`+rootJSON+`,`, "", 1),
		"null-xattrs":    strings.Replace(raw, xattrsJSON, "null", 1),
		"null-root":      strings.Replace(raw, rootJSON, "null", 1),
		"null-entries":   strings.Replace(raw, `"entries":`+string(marshal(t, m.Entries)), `"entries":null`, 1),
		"null-name":      strings.Replace(raw, `"name":"dXNlci7/"`, `"name":null`, 1),
		"null-value":     strings.Replace(raw, `"value":"AP8="`, `"value":null`, 1),
		"invalid-base64": strings.Replace(raw, `"name":"dXNlci7/"`, `"name":"user.ÿ"`, 1),
		"nul-name":       strings.Replace(raw, `"name":"dXNlci7/"`, `"name":"dXNlci4A"`, 1),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeManifest([]byte(data)); err == nil {
				t.Fatal("accepted invalid manifest")
			}
		})
	}
	// Keep the existing encoding/json scalar-null behavior; root validation
	// checks semantic values rather than adding a new wire schema.
	if _, err := DecodeManifest([]byte(strings.Replace(raw, `"mode":7`, `"mode":null`, 1))); err != nil {
		t.Fatal(err)
	}
}

func TestDecodeManifestByteBound(t *testing.T) {
	if MaxManifestBytes != 64*1024*1024 {
		t.Fatal("manifest limit changed")
	}
	raw := marshal(t, validManifest())
	bounded := make([]byte, MaxManifestBytes+1)
	copy(bounded, raw)
	for i := len(raw); i < len(bounded); i++ {
		bounded[i] = ' '
	}
	if _, err := DecodeManifest(bounded[:MaxManifestBytes]); err != nil {
		t.Fatalf("exact bound: %v", err)
	}
	if _, err := DecodeManifest(bounded); err == nil {
		t.Fatal("oversize accepted")
	}
}

func TestValidateManifestVariants(t *testing.T) {
	for name, mutate := range map[string]func(*Manifest){
		"version":           func(m *Manifest) { m.Version = 3 },
		"nil-root":          func(m *Manifest) { m.Root = nil },
		"nil-entries":       func(m *Manifest) { m.Entries = nil },
		"nil-xattrs":        func(m *Manifest) { m.Root.Xattrs = nil },
		"mode":              func(m *Manifest) { m.Root.Mode = unix.S_IFDIR | 0700 },
		"uid":               func(m *Manifest) { m.Root.UID = ^uint32(0) },
		"gid":               func(m *Manifest) { m.Root.GID = ^uint32(0) },
		"intent":            func(m *Manifest) { m.Intent = "00000000-0000-3000-8000-000000000001" },
		"intent-uppercase":  func(m *Manifest) { m.Intent = "00000000-0000-4000-A000-000000000001" },
		"inode-zero":        func(m *Manifest) { m.Entries[0].Identity = object(0, 1, unix.S_IFREG) },
		"inode-large":       func(m *Manifest) { m.Entries[0].Identity.Inode += 1 << 32 },
		"inode-handle":      func(m *Manifest) { m.Entries[0].Identity.Handle[0]++ },
		"generation-handle": func(m *Manifest) { m.Entries[0].Identity.Handle[4]++ },
		"handle-type":       func(m *Manifest) { m.Entries[0].Identity.HandleType = 2 },
		"handle-size":       func(m *Manifest) { m.Entries[0].Identity.HandleSize = 7 },
		"special-file":      func(m *Manifest) { m.Entries[0].Identity.FileType = unix.S_IFIFO },
	} {
		t.Run(name, func(t *testing.T) {
			m := validManifest()
			mutate(&m)
			if err := ValidateManifest(m); err == nil {
				t.Fatal("accepted invalid manifest")
			}
		})
	}
	m := validManifest()
	m.Entries = make([]Entry, MaxEntries+1)
	if err := ValidateManifest(m); err == nil {
		t.Fatal("entry bound ignored")
	}
	m.Entries = []Entry{}
	m.Physical = storageauthority.CopyRootV1{}
	m.Root.Filesystem, m.Root.Device, m.Root.Inode = [2]int32{}, 0, 0
	m.Root.Mode, m.Root.UID, m.Root.GID = 07777, ^uint32(0)-1, ^uint32(0)-1
	if err := ValidateManifest(m); err != nil {
		t.Fatalf("metadata mistaken for authority: %v", err)
	}
	if err := ValidateRootMetadata(nil); err == nil {
		t.Fatal("nil metadata accepted")
	}
}

func TestManifestPathsAndParents(t *testing.T) {
	m := validManifest()
	dir, file, link := object(1, 0, unix.S_IFDIR), object(2, 0, unix.S_IFREG), object(3, 0, unix.S_IFLNK)
	for _, entries := range [][]Entry{
		{{"a/b", file}}, {{"a/b", file}, {"a", dir}},
		{{"a", file}, {"a/b", file}}, {{"a", link}, {"a/b", file}},
		{{"a", dir}, {"a", dir}},
	} {
		m.Entries = entries
		if err := ValidateManifest(m); err == nil {
			t.Fatalf("accepted invalid tree %+v", entries)
		}
	}
	for _, name := range []string{"", "/a", "a/", "a//b", ".", "..", "a/../b", "a/./b", "a\x00b", TransactionName, TransactionName + "/a", strings.Repeat("x", 256)} {
		m.Entries = []Entry{{name, file}}
		if err := ValidateManifest(m); err == nil {
			t.Fatalf("accepted path %q", name)
		}
	}
	m.Entries = []Entry{{"a", dir}, {"a/" + TransactionName, link}, {"a/b", file}, {"hardlink", file}, {"\xff", file}}
	if err := ValidateManifest(m); err != nil {
		t.Fatal(err)
	}
	// Assert Linux limits even when tested on Darwin. Parent-before-child is
	// checked separately so syntax-only long paths need no huge manifest.
	for _, n := range []int{4095, 4096} {
		p := strings.Repeat(strings.Repeat("a", 255)+"/", 15) + strings.Repeat("b", n-15*256)
		_, ok := validPath(p)
		if ok != (n == 4095) {
			t.Fatalf("path bytes %d: valid=%v", n, ok)
		}
	}
	for _, n := range []int{255, 256} {
		_, ok := validPath(strings.TrimSuffix(strings.Repeat("a/", n), "/"))
		if ok != (n == 255) {
			t.Fatalf("path depth %d: valid=%v", n, ok)
		}
	}
	if !bytes.Equal(marshal(t, XattrName("")), []byte(`""`)) {
		t.Fatal("empty name encoding changed")
	}
}
