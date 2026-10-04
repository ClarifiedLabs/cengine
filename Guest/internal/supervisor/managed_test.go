package supervisor

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"dev.cengine/guest/internal/protocol"
)

const managedTestVolume = "11111111-1111-4111-8111-111111111111"
const managedTestPrepare = "22222222-2222-4222-8222-222222222222"
const managedTestRuntime = "33333333-3333-4333-8333-333333333333"
const managedTestReadOnly = "44444444-4444-4444-8444-444444444444"

func managedFixture() (protocol.WorkloadSpec, ManagedPlan) {
	spec := protocol.WorkloadSpec{ID: "container", Mounts: []protocol.Mount{
		{Kind: "bind", Source: "host", Destination: "/host"},
		{Kind: "volume", Source: managedTestVolume, Destination: "/data"},
		{Kind: "volume", Source: managedTestVolume, Destination: "/readonly", ReadOnly: true, NoCopy: true, Subpath: "sub"},
		{Kind: "tmpfs", Destination: "/tmp"},
		{Kind: "socket", Destination: "/socket"},
		{Kind: "volume", Source: "direct", Device: "/dev/vdc", Destination: "/direct"},
	}}
	plan := ManagedPlan{Container: spec.ID, Prepare: managedTestPrepare, SpecificationDigest: strings.Repeat("a", 64), Mounts: []ManagedMount{
		{Index: 1, Volume: managedTestVolume, Attachment: managedTestPrepare, Destination: "/data", Mode: "read-write"},
		{Index: 2, Volume: managedTestVolume, Attachment: managedTestPrepare, Destination: "/readonly", Mode: "read-only", NoCopy: true, Subpath: "sub"},
	}}
	return spec, plan
}

func TestManagedPlanMatchesEveryMountField(t *testing.T) {
	spec, plan := managedFixture()
	if err := validateManagedPlan(spec, plan); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*protocol.WorkloadSpec, *ManagedPlan){
		"container":               func(_ *protocol.WorkloadSpec, p *ManagedPlan) { p.Container = "other" },
		"container escape":        func(s *protocol.WorkloadSpec, p *ManagedPlan) { s.ID = "../other"; p.Container = s.ID },
		"digest":                  func(_ *protocol.WorkloadSpec, p *ManagedPlan) { p.SpecificationDigest = "bad" },
		"prepare":                 func(_ *protocol.WorkloadSpec, p *ManagedPlan) { p.Prepare = "bad" },
		"index":                   func(_ *protocol.WorkloadSpec, p *ManagedPlan) { p.Mounts[0].Index = 0 },
		"duplicate index":         func(_ *protocol.WorkloadSpec, p *ManagedPlan) { p.Mounts[1].Index = 1 },
		"volume":                  func(_ *protocol.WorkloadSpec, p *ManagedPlan) { p.Mounts[0].Volume = managedTestRuntime },
		"destination":             func(_ *protocol.WorkloadSpec, p *ManagedPlan) { p.Mounts[0].Destination = "/other" },
		"subpath":                 func(_ *protocol.WorkloadSpec, p *ManagedPlan) { p.Mounts[0].Subpath = "other" },
		"mode":                    func(_ *protocol.WorkloadSpec, p *ManagedPlan) { p.Mounts[0].Mode = "read-only" },
		"noCopy":                  func(_ *protocol.WorkloadSpec, p *ManagedPlan) { p.Mounts[0].NoCopy = true },
		"missing readonly nocopy": func(_ *protocol.WorkloadSpec, p *ManagedPlan) { p.Mounts = p.Mounts[:1] },
		"extra volume": func(s *protocol.WorkloadSpec, _ *ManagedPlan) {
			s.Mounts = append(s.Mounts, protocol.Mount{Kind: "volume", Source: managedTestVolume})
		},
		"injected attachment":        func(s *protocol.WorkloadSpec, _ *ManagedPlan) { s.Mounts[0].ManagedAttachment = managedTestRuntime },
		"direct volume substitution": func(s *protocol.WorkloadSpec, _ *ManagedPlan) { s.Mounts[1].Device = "/dev/vdc" },
		"split prepare attachment":   func(_ *protocol.WorkloadSpec, p *ManagedPlan) { p.Mounts[1].Attachment = managedTestRuntime },
		"symlink-style path": func(s *protocol.WorkloadSpec, p *ManagedPlan) {
			s.Mounts[1].Destination = "/../outside"
			p.Mounts[0].Destination = "/../outside"
		},
		"attachment path": func(_ *protocol.WorkloadSpec, p *ManagedPlan) { p.Mounts[0].Attachment = "../escape" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			s, p := managedFixture()
			change(&s, &p)
			if validateManagedPlan(s, p) == nil {
				t.Fatal("accepted invalid plan")
			}
		})
	}
}

func TestManagedPrepareOnceAndTerminalFailure(t *testing.T) {
	spec, plan := managedFixture()
	var state managedState
	if _, err := state.beginPrepare(spec, plan); err == nil {
		t.Fatal("prepare before configuration")
	}
	if err := state.configure(); err != nil {
		t.Fatal(err)
	}
	if state.configure() == nil {
		t.Fatal("configuration was not latched")
	}
	if replay, err := state.beginPrepare(spec, plan); replay || err != nil {
		t.Fatalf("first prepare: %v %v", replay, err)
	}
	state.prepared = true
	if replay, err := state.beginPrepare(spec, plan); !replay || err != nil {
		t.Fatalf("replay: %v %v", replay, err)
	}
	changed := plan
	changed.SpecificationDigest = strings.Repeat("b", 64)
	if _, err := state.beginPrepare(spec, changed); err == nil {
		t.Fatal("changed digest replay accepted")
	}
	changed = plan
	changed.Prepare = managedTestRuntime
	if _, err := state.beginPrepare(spec, changed); err == nil {
		t.Fatal("changed prepare replay accepted")
	}
	spec.Arguments = []string{"changed"}
	if _, err := state.beginPrepare(spec, plan); err == nil {
		t.Fatal("changed spec replay accepted")
	}
	spec, plan = managedFixture()
	state.failure = errors.New("copy-up failed")
	if _, err := state.beginPrepare(spec, plan); !errors.Is(err, state.failure) {
		t.Fatal("failed prepare replayed")
	}
	state = managedState{configured: true}
	invalid := plan
	invalid.Container = "other"
	if _, err := state.beginPrepare(spec, invalid); err == nil {
		t.Fatal("invalid plan accepted")
	}
	if _, err := state.beginPrepare(spec, plan); err == nil {
		t.Fatal("failed validation allowed retry")
	}
}

func TestManagedRuntimeRequiresExactFreshSlots(t *testing.T) {
	_, plan := managedFixture()
	rows := append([]ManagedMount(nil), plan.Mounts...)
	rows[0].Attachment = managedTestRuntime
	rows[1].Attachment = managedTestReadOnly
	mapping, err := runtimeManagedMounts(plan, rows)
	if err != nil || mapping[1] != managedTestRuntime || mapping[2] != managedTestReadOnly {
		t.Fatalf("runtime mapping: %v %v", mapping, err)
	}
	for _, mutate := range []func([]ManagedMount) []ManagedMount{
		func(m []ManagedMount) []ManagedMount { m[0].Attachment = managedTestPrepare; return m },
		func(m []ManagedMount) []ManagedMount { m[1].Attachment = managedTestRuntime; return m },
		func(m []ManagedMount) []ManagedMount { m[0].Mode = "read-only"; return m },
		func(m []ManagedMount) []ManagedMount { m[0].Index = m[1].Index; return m },
		func(m []ManagedMount) []ManagedMount { return m[:1] },
	} {
		if _, err := runtimeManagedMounts(plan, mutate(append([]ManagedMount(nil), rows...))); err == nil {
			t.Fatal("invalid runtime mapping accepted")
		}
	}
}

func TestManagedMetadataIsAdditiveAndNonsecret(t *testing.T) {
	mount := protocol.Mount{Kind: "volume"}
	data, err := json.Marshal(mount)
	if err != nil || strings.Contains(string(data), "managedAttachment") {
		t.Fatalf("absent metadata: %s %v", data, err)
	}
	mount.ManagedAttachment = managedTestRuntime
	data, err = json.Marshal(mount)
	if err != nil {
		t.Fatal(err)
	}
	var decoded protocol.Mount
	if err := json.Unmarshal(data, &decoded); err != nil || decoded.ManagedAttachment != managedTestRuntime {
		t.Fatalf("metadata roundtrip: %+v %v", decoded, err)
	}
	if protocol.Version != 19 {
		t.Fatal("unexpected version change")
	}
}

func TestManagedAttachmentPathRejectsNonUUIDAndEscapes(t *testing.T) {
	if path, err := managedAttachmentPath(managedTestRuntime); err != nil || path != managedMountRoot+"/"+managedTestRuntime+"/root" {
		t.Fatalf("path: %q %v", path, err)
	}
	for _, invalid := range []string{"", "../root", "/run/other", strings.Replace(managedTestRuntime, "4333", "1333", 1), strings.Replace(managedTestRuntime, "8333", "7333", 1), managedTestRuntime + "/root"} {
		if _, err := managedAttachmentPath(invalid); err == nil {
			t.Fatalf("accepted %q", invalid)
		}
	}
}
