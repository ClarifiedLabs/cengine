package preparecompat

import (
	"bytes"
	"crypto/sha256"
	a "dev.cengine/guest/internal/storageauthority"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func vectorArm(t *testing.T) Arm {
	t.Helper()
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v []struct{ Arm Arm }
	if json.Unmarshal(raw, &v) != nil {
		t.Fatal("vectors")
	}
	return v[0].Arm
}
func TestCanonicalInteropVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Name              string
		Arm               json.RawMessage
		Canonical, SHA256 string
	}
	if json.Unmarshal(raw, &vectors) != nil {
		t.Fatal("vectors")
	}
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			arm, err := DecodeArm(v.Arm)
			if err != nil {
				t.Fatal(err)
			}
			b, err := CanonicalArmData(arm)
			if err != nil || string(b) != v.Canonical {
				t.Fatalf("canonical mismatch %s %v", b, err)
			}
			digest, err := ArmDigest(arm)
			if err != nil || digest != v.SHA256 {
				t.Fatal("digest mismatch", digest, err)
			}
		})
	}
}
func TestArmClosedCodec(t *testing.T) {
	a := vectorArm(t)
	raw, _ := CanonicalArmData(a)
	invalid := [][]byte{append(append([]byte{}, raw...), raw...), bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1), bytes.Replace(raw, []byte(`"version":1`), []byte(`"Version":1`), 1), bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1.0`), 1), bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":null`), 1), bytes.Replace(raw, []byte(`"subpath":""`), []byte(`"subpath":"\ud800"`), 1), bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"unknown":true`), 1)}
	for n, b := range invalid {
		if _, err := DecodeArm(b); err == nil {
			t.Fatalf("accepted invalid %d", n)
		}
	}
	mutations := map[string]func(*Arm){"profile": func(a *Arm) { a.Profile = "ordinary" }, "runtime-target": func(a *Arm) { a.TargetAttachment = a.Slots[0].Attachment }, "missing-runtime": func(a *Arm) { a.Slots = a.Slots[1:] }, "duplicate-slot": func(a *Arm) { a.Slots = append(a.Slots, a.Slots[0]) }, "duplicate-key": func(a *Arm) { a.Credentials[1].Key = a.Credentials[0].Key }, "missing-credential": func(a *Arm) { a.Credentials = a.Credentials[:1] }, "runtime-credential": func(a *Arm) { a.Credentials[0].Attachment = a.Slots[0].Attachment }, "nocopy": func(a *Arm) { a.Mounts[1].NoCopy = true }, "subpath": func(a *Arm) { a.Mounts[1].Subpath = "x" }, "read-only": func(a *Arm) { a.Mounts[1].Mode = "read-only" }, "binding": func(a *Arm) { a.Binding.ShimLaunchUUID = a.RequestID }, "nil": func(a *Arm) { a.Mounts = nil }, "utf8": func(a *Arm) { a.Mounts[1].Destination = "/\xff" }, "oversize": func(a *Arm) {
		for i := uint32(3); i < 24; i++ {
			m := a.Mounts[0]
			m.Index = i
			m.Destination = "/" + strings.Repeat("x", 4095)
			a.Mounts = append(a.Mounts, m)
		}
	}}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			arm := vectorArm(t)
			mutate(&arm)
			if _, err := CanonicalArmData(arm); err == nil {
				t.Fatal("accepted invalid arm")
			}
		})
	}
}
func object(n uint32, kind uint32) a.Ext4ObjectV1 {
	o := a.Ext4ObjectV1{Inode: uint64(n), Generation: 7, FileType: kind, HandleType: 1, HandleSize: 8}
	binary.LittleEndian.PutUint32(o.Handle[:4], n)
	binary.LittleEndian.PutUint32(o.Handle[4:], 7)
	return o
}
func TestObjectIdentityBounds(t *testing.T) {
	o := object(42, 16384)
	if _, err := ObjectFromAuthority(o); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*a.Ext4ObjectV1){func(o *a.Ext4ObjectV1) { o.Inode = 1 << 32 }, func(o *a.Ext4ObjectV1) { o.HandleType = 2 }, func(o *a.Ext4ObjectV1) { o.HandleSize = 7 }, func(o *a.Ext4ObjectV1) { o.Handle[0]++ }, func(o *a.Ext4ObjectV1) { o.Generation++ }, func(o *a.Ext4ObjectV1) { o.FileType = 40960 }} {
		bad := o
		mutate(&bad)
		if _, err := ObjectFromAuthority(bad); err == nil {
			t.Fatal("invalid identity accepted")
		}
	}
}
func testObservation(t *testing.T, arm Arm) Observation {
	t.Helper()
	digest, err := ArmDigest(arm)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := ObjectFromAuthority(object(1, 16384))
	tx, _ := ObjectFromAuthority(object(2, 16384))
	p, _ := ObjectFromAuthority(object(3, 32768))
	s, _ := ObjectFromAuthority(object(4, 32768))
	return Observation{SourceAtimes: SourceAtimes{Root: 0, A: 17, Z: 1<<63 - 1}, Version: 1, Profile: Profile, RequestID: arm.RequestID, ArmDigest: digest, Stage: "first-child-published", Count: 1, TargetAttachment: arm.TargetAttachment, CopyIntent: arm.Scope.Intent, FilesystemUUID: strings.Repeat("1", 32), ManifestDigest: strings.Repeat("a", 64), ManifestSize: 100, Root: r, Transaction: tx, Published: p, Staged: s}
}
func TestObservationClosedCodec(t *testing.T) {
	o := testObservation(t, vectorArm(t))
	b, _ := CanonicalJSON(o)
	if _, err := DecodeObservation(b); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Observation){"count": func(o *Observation) { o.Count = 2 }, "stage": func(o *Observation) { o.Stage = "complete" }, "fs": func(o *Observation) { o.FilesystemUUID = strings.Repeat("0", 32) }, "size": func(o *Observation) { o.ManifestSize = 0 }, "file": func(o *Observation) { o.Published.FileType = 16384 }, "handle": func(o *Observation) { o.Staged.Handle = "0000000000000000" }} {
		t.Run(name, func(t *testing.T) {
			bad := o
			mutate(&bad)
			if ValidateObservation(bad) == nil {
				t.Fatal("accepted")
			}
		})
	}
	if _, err := DecodeObservation(bytes.Replace(b, []byte(`"count":1`), []byte(`"count":1,"path":"/secret"`), 1)); err == nil {
		t.Fatal("path accepted")
	}
}

func TestObservationInteropVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/observation-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Name              string
		Observation       json.RawMessage
		Canonical, SHA256 string
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			o, err := DecodeObservation(v.Observation)
			if err != nil {
				t.Fatal(err)
			}
			canonical, err := CanonicalJSON(o)
			if err != nil || string(canonical) != v.Canonical {
				t.Fatal("canonical observation mismatch", err)
			}
			sum := sha256.Sum256(canonical)
			if hex.EncodeToString(sum[:]) != v.SHA256 {
				t.Fatal("observation digest mismatch")
			}
		})
	}
}
func TestSourceAtimesClosedRequiredRange(t *testing.T) {
	o := testObservation(t, vectorArm(t))
	raw, err := CanonicalJSON(o)
	if err != nil {
		t.Fatal(err)
	}
	// Zero and MaxInt64 nanoseconds are valid; UInt64 and JSON decoding must not
	// silently widen the signed timestamp contract.
	if _, err := DecodeObservation(raw); err != nil {
		t.Fatal(err)
	}
	const field = `"sourceAtimes":{"a":17,"root":0,"z":9223372036854775807}`
	replacements := map[string]string{
		"missing": "", "null": `"sourceAtimes":null`, "missing-root": `"sourceAtimes":{"a":17,"z":1}`,
		"missing-a": `"sourceAtimes":{"root":0,"z":1}`, "missing-z": `"sourceAtimes":{"root":0,"a":1}`,
		"nested-null": `"sourceAtimes":{"root":null,"a":17,"z":1}`,
		"overflow":    `"sourceAtimes":{"root":9223372036854775808,"a":17,"z":1}`,
		"negative":    `"sourceAtimes":{"root":-1,"a":17,"z":1}`,
		"fraction":    `"sourceAtimes":{"root":0.5,"a":17,"z":1}`,
		"unknown":     `"sourceAtimes":{"root":0,"a":17,"z":1,"extra":0}`,
		"duplicate":   `"sourceAtimes":{"root":0,"root":1,"a":17,"z":1}`,
	}
	for name, replacement := range replacements {
		t.Run(name, func(t *testing.T) {
			old := field
			if replacement == "" {
				old += ","
			}
			bad := bytes.Replace(raw, []byte(old), []byte(replacement), 1)
			if bytes.Equal(raw, bad) {
				t.Fatal("mutation did not apply")
			}
			if _, err := DecodeObservation(bad); err == nil {
				t.Fatal("invalid source atimes accepted")
			}
		})
	}
	for _, mutate := range []func(*SourceAtimes){func(a *SourceAtimes) { a.Root = 1 << 63 }, func(a *SourceAtimes) { a.A = 1 << 63 }, func(a *SourceAtimes) { a.Z = 1 << 63 }} {
		bad := o
		mutate(&bad.SourceAtimes)
		if ValidateObservation(bad) == nil {
			t.Fatal("overflow accepted")
		}
	}
}
