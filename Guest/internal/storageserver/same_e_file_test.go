package storageserver

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	cc "dev.cengine/guest/internal/consumercompat"
	pc "dev.cengine/guest/internal/preparecompat"
	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
)

func fileArm(t *testing.T) cc.Arm {
	q := recorderArm(t)
	q.Version, q.CaseName = cc.SameEFileVersion, cc.SameEFile
	q.Original.Epoch = q.WorkerScope.ServiceEpoch
	return q
}

func TestSameEFileVersionGate(t *testing.T) {
	q := fileArm(t)
	must(t, cc.ValidateArm(q))
	for _, version := range []uint32{3, 4, 5, 6, 9} {
		bad := q
		bad.Version = version
		if cc.ValidateArm(bad) == nil {
			t.Fatal("file case accepted wrong version", version)
		}
	}
	for _, mutate := range []func(*cc.Arm){
		func(q *cc.Arm) { q.CaseName = cc.SameE },
		func(q *cc.Arm) { q.CaseName = cc.SameEReconnect },
		func(q *cc.Arm) { q.CaseName = cc.CrossE },
		func(q *cc.Arm) { q.CaseName = cc.WrongEpoch },
		func(q *cc.Arm) { q.Original.Epoch = string(id(t)) },
		func(q *cc.Arm) { q.Original.Binding.Mode = "read-only" },
		func(q *cc.Arm) { q.Original.Binding.Role = "prepare" },
	} {
		bad := q
		mutate(&bad)
		if cc.ValidateArm(bad) == nil {
			t.Fatal("version 7 widened", bad)
		}
	}
}

func TestSameEFileAdmissionAndFinalize(t *testing.T) {
	for _, kind := range []string{"exact-caller", "exact-grant", "opcode", "node", "handle", "offset", "empty", "size", "payload", "invalid-auth", "invalid-caller", "prepare", "epoch", "store", "volume", "attachment", "container", "launch", "key", "role", "mode", "leaf", "unestablished", "post-arm", "active", "canceled", "wrapped-blocked", "zero-sequence", "expired", "duplicate", "other-connection", "closed", "query-mismatch", "finalize-race", "duplicate-finalize-race"} {
		t.Run(kind, func(t *testing.T) {
			o := NewConsumerObservation()
			defer o.Close()
			q := fileArm(t)
			c := consumerFrom(o.Context(context.Background()))
			if c != nil {
				c.established = time.Now().Add(-time.Second)
			}
			_, err := o.Arm(q)
			if pc.CurrentProfile() != pc.FullProfile {
				if err == nil {
					t.Fatal("ordinary collector enabled")
				}
				return
			}
			must(t, err)
			if _, err := o.Finalize(q); err == nil {
				t.Fatal("sealed without evidence")
			}
			b := q.Original.Binding
			h := a.DataHello{Epoch: a.ID(q.Original.Epoch), Binding: a.Binding{Store: a.ID(b.Store), Volume: a.ID(b.Volume), Attachment: a.ID(b.Attachment), Container: a.ContainerID(b.Container), Launch: a.ID(b.Launch), Key: a.Fingerprint(b.Key), Role: a.Role(b.Role), Mode: a.Mode(b.Mode)}}
			var leaf [32]byte
			raw, _ := hex.DecodeString(q.OriginalLeafSHA256)
			copy(leaf[:], raw)
			write := w.WriteRequest{Node: 99, Handle: 42, Data: []byte{0x5a}}
			request := w.Request{Sequence: 17, Auth: w.Auth{Kind: w.CallerAuth, Caller: &w.Caller{Groups: []uint32{}}}}
			result := a.ErrBlocked
			switch kind {
			case "exact-grant":
				request.Auth = w.Auth{Kind: w.OpenGrantAuth}
			case "node":
				write.Node = 0
			case "handle":
				write.Handle = 0
			case "offset":
				write.Offset = 1
			case "empty":
				write.Data = nil
			case "size":
				write.Data = []byte{0x5a, 0x5a}
			case "payload":
				write.Data[0] = 0x59
			case "invalid-auth":
				request.Auth = w.Auth{Kind: w.NodeMetadataAuth}
			case "invalid-caller":
				request.Auth.Caller = nil
			case "prepare":
				h.Binding.Prepare = id(t)
			case "epoch":
				h.Epoch = id(t)
			case "store":
				h.Binding.Store = id(t)
			case "volume":
				h.Binding.Volume = id(t)
			case "attachment":
				h.Binding.Attachment = id(t)
			case "container":
				h.Binding.Container = a.ContainerID(strings.Repeat("e", 64))
			case "launch":
				h.Binding.Launch = id(t)
			case "key":
				h.Binding.Key = a.Fingerprint(strings.Repeat("e", 64))
			case "role":
				h.Binding.Role = a.PrepareRole
			case "mode":
				h.Binding.Mode = a.ReadOnly
			case "leaf":
				leaf[0]++
			case "unestablished":
				c.established = time.Time{}
			case "post-arm":
				c.established = time.Now()
			case "active":
				result = nil
			case "canceled":
				result = context.Canceled
			case "wrapped-blocked":
				result = fmt.Errorf("wrapped: %w", a.ErrBlocked)
			case "zero-sequence":
				request.Sequence = 0
			case "expired":
				o.mu.Lock()
				o.armedAt = time.Now().Add(-11 * time.Second)
				o.mu.Unlock()
			case "closed":
				o.Close()
			case "query-mismatch":
				bad := q
				bad.OperationUUID = string(id(t))
				if _, err := o.Query(bad); err == nil {
					t.Fatal("query mismatch")
				}
			}
			request.Body = write
			if kind == "opcode" {
				request.Body = w.GetAttrRequest{Node: 99}
			}
			var sealed cc.Status
			var sealErr error
			var done chan struct{}
			seal := func() { sealed, sealErr = o.Finalize(q); close(done) }
			if kind == "finalize-race" {
				done = make(chan struct{})
				go seal()
			}
			c.admission(h, leaf, request, result)
			if kind == "duplicate-finalize-race" {
				done = make(chan struct{})
				go seal()
			}
			if kind == "duplicate" || kind == "duplicate-finalize-race" {
				c.admission(h, leaf, request, result)
			}
			if kind == "other-connection" {
				other := consumerFrom(o.Context(context.Background()))
				other.established = c.established
				other.admission(h, leaf, request, result)
			}
			if done != nil {
				<-done
			}
			s, err := o.Query(q)
			must(t, err)
			must(t, cc.ValidateStatus(s))
			positive := strings.HasPrefix(kind, "exact-") || kind == "finalize-race" || kind == "duplicate-finalize-race" && sealErr == nil
			if !positive {
				if s.Evidence != nil || s.State == "observed" || s.State == "finalized" {
					t.Fatal("false write proof", s)
				}
				if _, err := o.Finalize(q); err == nil {
					t.Fatal("sealed false proof")
				}
				return
			}
			if done != nil && sealErr == nil {
				must(t, cc.ValidateStatus(sealed))
			}
			p := s.Evidence.Admission
			if p.Operation != w.OpWrite || p.Node != write.Node || p.Handle != write.Handle || p.RequestSequence != request.Sequence || p.AuthKind != request.Auth.Kind || !p.WriteOneAtZero || p.NoHandle {
				t.Fatal("not actual request", p)
			}
			encoded, err := json.Marshal(p)
			must(t, err)
			if !strings.Contains(string(encoded), `"handle":42`) || !strings.Contains(string(encoded), `"writeOneAtZero":true`) || strings.Contains(string(encoded), `"noHandle"`) {
				t.Fatal(string(encoded))
			}
			for _, mutate := range []func(*cc.Admission){
				func(p *cc.Admission) { p.Operation = w.OpGetAttr },
				func(p *cc.Admission) { p.Node = 0 },
				func(p *cc.Admission) { p.Handle = 0 },
				func(p *cc.Admission) { p.WriteOneAtZero = false },
				func(p *cc.Admission) { p.NoHandle = true },
				func(p *cc.Admission) { p.AuthKind = 0 },
				func(p *cc.Admission) { p.AuthKind = w.NodeMetadataAuth },
				func(p *cc.Admission) { p.AuthKind = w.LifecycleAuth },
				func(p *cc.Admission) { p.RequestSequence = 0 },
				func(p *cc.Admission) { p.Original.Binding.Key = "wrong" },
			} {
				bad, err := o.Query(q)
				must(t, err)
				mutate(bad.Evidence.Admission)
				if cc.ValidateStatus(bad) == nil {
					t.Fatal("accepted incomplete write proof")
				}
			}
			terminal, err := o.Finalize(q)
			must(t, err)
			terminal.Evidence.Admission.Handle++
			terminal.Evidence.Admission.WriteOneAtZero = false
			c.admission(h, leaf, request, nil)
			o.Close()
			again, err := o.Finalize(q)
			must(t, err)
			must(t, cc.ValidateStatus(again))
			if again.Evidence.Admission.Handle != write.Handle || !again.Evidence.Admission.WriteOneAtZero {
				t.Fatal("aliased terminal proof")
			}
		})
	}
}

// Host-side source contract: the observer receives the actual decoded request,
// authenticated peer tuple/leaf and unmodified authority result, before error exit.
func TestSameEFileRealAdmissionBoundarySource(t *testing.T) {
	raw, err := os.ReadFile("server.go")
	must(t, err)
	source := string(raw)
	boundary := "guard, err := authority.Admit(p.principal, p.hello.Binding.Volume, mutates)\n\t\tp.consumer.admission(p.hello, p.consumerLeaf, request, err)"
	if strings.Count(source, boundary) != 1 {
		t.Fatal("passive observer is not directly after real Authority.Admit")
	}
	for _, actual := range []string{
		"p.consumerLeaf = sha256.Sum256(state.PeerCertificates[0].Raw)",
		"p.hello = a.DataHello{Epoch: hello.Epoch, Binding: binding}",
		"principal, err := authority.AuthenticateData(ctx, p.conn, client.Authority)",
		"case <-p.rootWritten:",
		"p.consumer.established = time.Now()",
		"request, err := p.readRequest()",
		"if err = sequence.Accept(request.Sequence); err != nil",
	} {
		if !strings.Contains(source, actual) {
			t.Fatal("missing real observation source", actual)
		}
	}
	if strings.Index(source, "case <-p.rootWritten:") > strings.Index(source, "p.consumer.established = time.Now()") {
		t.Fatal("connection marked established before real root reply")
	}
}
