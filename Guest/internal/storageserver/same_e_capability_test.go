package storageserver

import (
	"context"
	cc "dev.cengine/guest/internal/consumercompat"
	pc "dev.cengine/guest/internal/preparecompat"
	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
	"encoding/hex"
	"testing"
	"time"
)

func TestSameECapabilityActualAdmission(t *testing.T) {
	for _, fault := range []string{"exact", "name", "nul", "node", "auth", "caller", "write", "active", "canceled", "sequence", "leaf", "new-connection", "prepare", "duplicate"} {
		t.Run(fault, func(t *testing.T) {
			o := NewConsumerObservation()
			defer o.Close()
			q := fileArm(t)
			q.Version = cc.SameEFileXattrVersion
			c := consumerFrom(o.Context(context.Background()))
			if c != nil {
				c.established = time.Now().Add(-time.Second)
			}
			_, err := o.Arm(q)
			if pc.CurrentProfile() != pc.FullProfile {
				if err == nil {
					t.Fatal("ordinary enabled")
				}
				return
			}
			must(t, err)
			b := q.Original.Binding
			h := a.DataHello{Epoch: a.ID(q.Original.Epoch), Binding: a.Binding{Store: a.ID(b.Store), Volume: a.ID(b.Volume), Attachment: a.ID(b.Attachment), Container: a.ContainerID(b.Container), Launch: a.ID(b.Launch), Key: a.Fingerprint(b.Key), Role: a.RuntimeRole, Mode: a.ReadWrite}}
			var leaf [32]byte
			raw, _ := hex.DecodeString(q.OriginalLeafSHA256)
			copy(leaf[:], raw)
			get := w.GetXAttrRequest{Node: 99, Name: []byte(cc.SameEFileCapability), Size: 20}
			request := w.Request{Sequence: 17, Auth: w.Auth{Kind: w.CallerAuth, Caller: &w.Caller{Groups: []uint32{}}}}
			result := a.ErrBlocked
			switch fault {
			case "name":
				get.Name = []byte("user.capability")
			case "nul":
				get.Name = append(get.Name, 0)
			case "node":
				get.Node = 0
			case "auth":
				request.Auth = w.Auth{Kind: w.NodeMetadataAuth}
			case "caller":
				request.Auth.Caller = nil
			case "active":
				result = nil
			case "canceled":
				result = context.Canceled
			case "sequence":
				request.Sequence = 0
			case "leaf":
				leaf[0]++
			case "new-connection":
				c.established = time.Now()
			case "prepare":
				h.Binding.Prepare = id(t)
			}
			request.Body = get
			if fault == "write" {
				request.Body = w.WriteRequest{Node: 99, Handle: 42, Data: []byte{0x5a}}
			}
			c.admission(h, leaf, request, result)
			if fault == "duplicate" {
				c.admission(h, leaf, request, result)
			}
			status, err := o.Query(q)
			must(t, err)
			must(t, cc.ValidateStatus(status))
			if fault != "exact" {
				if status.Evidence != nil {
					t.Fatal("false capability proof", status)
				}
				return
			}
			proof := status.Evidence.Admission
			if proof.Node != 99 || proof.RequestSequence != 17 || proof.CapabilityName != cc.SameEFileCapability || proof.Operation != w.OpGetXAttr || !proof.NoHandle || proof.Handle != 0 {
				t.Fatal(proof)
			}
			for _, mutate := range []func(*cc.Admission){
				func(p *cc.Admission) { p.CapabilityName = "" }, func(p *cc.Admission) { p.Handle = 42 }, func(p *cc.Admission) { p.WriteOneAtZero = true }, func(p *cc.Admission) { p.NoHandle = false }, func(p *cc.Admission) { p.AuthKind = w.OpenGrantAuth }, func(p *cc.Admission) { p.Operation = w.OpWrite },
			} {
				bad, err := o.Query(q)
				must(t, err)
				mutate(bad.Evidence.Admission)
				if cc.ValidateStatus(bad) == nil {
					t.Fatal("mixed proof")
				}
			}
			final, err := o.Finalize(q)
			must(t, err)
			must(t, cc.ValidateStatus(final))
			legacy := final
			legacy.Query.Version = cc.SameEFileVersion
			if cc.ValidateStatus(legacy) == nil {
				t.Fatal("capability reinterpreted as legacy WRITE")
			}
		})
	}
}
