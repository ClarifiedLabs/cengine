package storageauthority

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"strings"
	"testing"
)

func TestContainerIdentityIsHostHexNotGenerationUUID(t *testing.T) {
	f := newLifecycleWorkloadFixture(t, nil)
	v := f.volume("identities")
	valid := []ContainerID{ContainerID(strings.Repeat("0", 64)), ContainerID(strings.Repeat("0123456789abcdef", 4))}
	for _, id := range valid {
		b, key := f.binding(v, RuntimeRole, ReadWrite, "")
		b.Container = id
		must(t, f.a.RegisterAttachment(f.control, RegisterRequest{mustID(t), b}))
		wire, err := json.Marshal(b)
		must(t, err)
		var copy Binding
		must(t, json.Unmarshal(wire, &copy))
		if copy != b {
			t.Fatal("binding identity changed on JSON round trip")
		}
		conn := f.conn(key, tls.VersionTLS13, true)
		different := b
		different.Container = mustContainerID(t)
		_, err = f.a.AuthenticateData(context.Background(), conn, DataHello{f.a.Epoch(), different})
		wantErr(t, err, ErrUnauthorized)
		p, err := f.a.AuthenticateData(context.Background(), conn, DataHello{f.a.Epoch(), copy})
		must(t, err)
		guard, err := f.a.Admit(p, v.ID, true)
		must(t, err)
		guard.Release()
	}
	for _, id := range []ContainerID{"", ContainerID(mustID(t)), ContainerID(strings.Repeat("a", 63)), ContainerID(strings.Repeat("a", 65)), ContainerID(strings.Repeat("A", 64)), ContainerID(strings.Repeat("g", 64)), ContainerID(strings.Repeat("a", 63) + "\x00")} {
		b, _ := f.binding(v, RuntimeRole, ReadWrite, "")
		b.Container = id
		wantErr(t, f.a.RegisterAttachment(f.control, RegisterRequest{mustID(t), b}), ErrInvalid)
		prep := mustID(t)
		b.Role = PrepareRole
		b.Prepare = prep
		wantErr(t, f.a.ReservePrepare(f.control, ReserveRequest{mustID(t), prep, []Binding{b}}), ErrInvalid)
	}
	must(t, f.a.Close())
	var err error
	f.a, err = f.openCurrent()
	must(t, err)
	must(t, f.a.validate())
}

func TestLaunchRequiresSeparateFreshUUID(t *testing.T) {
	f := newLifecycleWorkloadFixture(t, nil)
	v := f.volume("launch")
	b, _ := f.binding(v, RuntimeRole, ReadWrite, "")
	for _, launch := range []ID{"", ID(b.Container), "container:pid:timestamp", "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"} {
		bad := b
		bad.Launch = launch
		wantErr(t, f.a.RegisterAttachment(f.control, RegisterRequest{mustID(t), bad}), ErrInvalid)
	}
	req := RegisterRequest{mustID(t), b}
	must(t, f.a.RegisterAttachment(f.control, req))
	req.Binding.Launch = mustID(t)
	wantErr(t, f.a.RegisterAttachment(f.control, req), ErrConflict)
}
