package storageserver

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	cc "dev.cengine/guest/internal/consumercompat"
	pc "dev.cengine/guest/internal/preparecompat"
	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
)

func TestSameERootAdmissionExactRequestAndLegacyShape(t *testing.T) {
	for _, kind := range []string{"exact", "legacy", "opcode", "node", "zero-root", "handle", "zero-handle", "caller-auth", "open-grant-auth", "caller-payload", "prepare", "post-arm", "not-blocked", "zero-sequence"} {
		t.Run(kind, func(t *testing.T) {
			o := NewConsumerObservation()
			defer o.Close()
			q := recorderArm(t)
			q.Version, q.CaseName = cc.SameERootVersion, cc.SameE
			q.Original.Epoch = q.WorkerScope.ServiceEpoch
			if kind == "legacy" {
				q.Version = cc.Version
			}
			ctx := o.Context(context.Background())
			c := consumerFrom(ctx)
			if c != nil {
				c.established, c.rootNode = time.Now().Add(-time.Second), 99
			}
			_, err := o.Arm(q)
			if pc.CurrentProfile() != pc.FullProfile {
				if err == nil {
					t.Fatal("ordinary collector enabled")
				}
				return
			}
			must(t, err)
			b := q.Original.Binding
			h := a.DataHello{Epoch: a.ID(q.Original.Epoch), Binding: a.Binding{Store: a.ID(b.Store), Volume: a.ID(b.Volume), Attachment: a.ID(b.Attachment), Container: a.ContainerID(b.Container), Launch: a.ID(b.Launch), Key: a.Fingerprint(b.Key), Role: a.Role(b.Role), Mode: a.Mode(b.Mode)}}
			var leaf [32]byte
			raw, _ := hex.DecodeString(q.OriginalLeafSHA256)
			copy(leaf[:], raw)
			request := w.Request{Sequence: 17, Auth: w.Auth{Kind: w.NodeMetadataAuth}, Body: w.GetAttrRequest{Node: 99}}
			result := a.ErrBlocked
			switch kind {
			case "opcode":
				request.Body = w.StatFSRequest{}
			case "node":
				request.Body = w.GetAttrRequest{Node: 100}
			case "zero-root":
				c.rootNode = 0
			case "handle", "zero-handle":
				handle := w.HandleID(42)
				if kind == "zero-handle" {
					handle = 0
				}
				request.Body = w.GetAttrRequest{Node: 99, Handle: &handle}
			case "caller-auth":
				request.Auth = w.Auth{Kind: w.CallerAuth, Caller: &w.Caller{Groups: []uint32{}}}
			case "open-grant-auth":
				request.Auth.Kind = w.OpenGrantAuth
			case "caller-payload":
				request.Auth.Caller = &w.Caller{Groups: []uint32{}}
			case "prepare":
				h.Binding.Prepare = id(t)
			case "post-arm":
				c.established = time.Now()
			case "not-blocked":
				result = nil
			case "zero-sequence":
				request.Sequence = 0
			}
			c.admission(h, leaf, request, result)
			s, err := o.Query(q)
			must(t, err)
			must(t, cc.ValidateStatus(s))
			if kind != "exact" && kind != "legacy" {
				if s.State != "failed" || s.Evidence != nil {
					t.Fatal("mismatch became root proof", s)
				}
				if _, err = o.Finalize(q); err == nil {
					t.Fatal("sealed mismatched request")
				}
				return
			}
			if s.State != "observed" || s.Evidence.Admission.RequestSequence != request.Sequence {
				t.Fatal(s)
			}
			proof := s.Evidence.Admission
			encoded, err := json.Marshal(proof)
			must(t, err)
			for _, field := range []string{"operation", "node", "authKind", "noHandle"} {
				if strings.Contains(string(encoded), `"`+field+`":`) != (kind == "exact") {
					t.Fatal("versioned DTO shape", string(encoded))
				}
			}
			for _, field := range []string{"handle", "writeOneAtZero"} {
				if strings.Contains(string(encoded), `"`+field+`":`) {
					t.Fatal("new fields leaked into old DTO", string(encoded))
				}
			}
			for _, mutate := range []func(*cc.Admission){
				func(p *cc.Admission) { p.Handle = 42 },
				func(p *cc.Admission) { p.WriteOneAtZero = true },
			} {
				bad, err := o.Query(q)
				must(t, err)
				mutate(bad.Evidence.Admission)
				if cc.ValidateStatus(bad) == nil {
					t.Fatal("new fields accepted in old DTO")
				}
			}
			if kind == "exact" {
				if proof.Operation != w.OpGetAttr || proof.Node != 99 || proof.AuthKind != w.NodeMetadataAuth || !proof.NoHandle {
					t.Fatal(proof)
				}
				for _, mutate := range []func(*cc.Admission){
					func(p *cc.Admission) { p.Operation = "" },
					func(p *cc.Admission) { p.Operation = w.OpStatFS },
					func(p *cc.Admission) { p.Node = 0 },
					func(p *cc.Admission) { p.AuthKind = w.CallerAuth },
					func(p *cc.Admission) { p.NoHandle = false },
				} {
					bad, err := o.Query(q)
					must(t, err)
					mutate(bad.Evidence.Admission)
					if cc.ValidateStatus(bad) == nil {
						t.Fatal("accepted incomplete operation proof")
					}
				}
			}
			terminal, err := o.Finalize(q)
			must(t, err)
			terminal.Evidence.Admission.Node++
			again, err := o.Finalize(q)
			must(t, err)
			if again.Evidence.Admission.Node != proof.Node {
				t.Fatal("aliased operation snapshot")
			}
		})
	}
}

func TestSameERootVersionGate(t *testing.T) {
	q := recorderArm(t)
	q.Version, q.CaseName = cc.SameERootVersion, cc.SameE
	q.Original.Epoch = q.WorkerScope.ServiceEpoch
	must(t, cc.ValidateArm(q))
	for _, name := range []string{cc.CrossE, cc.SameEReconnect, cc.WrongEpoch} {
		bad := q
		bad.CaseName = name
		if cc.ValidateArm(bad) == nil {
			t.Fatal("version 6 widened", name)
		}
	}
	q.Original.Epoch = string(id(t))
	if cc.ValidateArm(q) == nil {
		t.Fatal("version 6 changed E")
	}
}
