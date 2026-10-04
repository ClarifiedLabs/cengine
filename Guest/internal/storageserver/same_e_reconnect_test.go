package storageserver

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	cc "dev.cengine/guest/internal/consumercompat"
	pc "dev.cengine/guest/internal/preparecompat"
	a "dev.cengine/guest/internal/storageauthority"
)

func TestSameEReconnectGateAndBounds(t *testing.T) {
	q := recorderArm(t)
	q.Version, q.CaseName = cc.SameEReconnectVersion, cc.SameEReconnect
	q.Original.Epoch = q.WorkerScope.ServiceEpoch
	must(t, cc.ValidateArm(q))
	for _, version := range []uint32{3, 4, 6} {
		bad := q
		bad.Version = version
		if cc.ValidateArm(bad) == nil {
			t.Fatal("reconnect version accepted", version)
		}
	}
	for _, name := range []string{cc.SameE, cc.CrossE, cc.WrongEpoch} {
		bad := q
		bad.CaseName = name
		if cc.ValidateArm(bad) == nil {
			t.Fatal("version 5 widened", name)
		}
	}
	for _, kind := range []string{"exact", "finalize-race", "duplicate-finalize-race", "pre-arm", "prepare", "canceled", "expired", "success", "conflict", "duplicate", "closed"} {
		t.Run(kind, func(t *testing.T) {
			o := NewConsumerObservation()
			defer o.Close()
			ctx := o.Context(context.Background())
			_, err := o.Arm(q)
			if pc.CurrentProfile() != pc.FullProfile {
				if err == nil {
					t.Fatal("ordinary collector enabled")
				}
				return
			}
			must(t, err)
			if kind != "pre-arm" {
				ctx = o.Context(context.Background())
			}
			b := q.Original.Binding
			h := a.DataHello{Epoch: a.ID(q.Original.Epoch), Binding: a.Binding{Store: a.ID(b.Store), Volume: a.ID(b.Volume), Attachment: a.ID(b.Attachment), Container: a.ContainerID(b.Container), Launch: a.ID(b.Launch), Key: a.Fingerprint(b.Key), Role: a.Role(b.Role), Mode: a.Mode(b.Mode)}}
			var leaf [32]byte
			raw, _ := hex.DecodeString(q.OriginalLeafSHA256)
			copy(leaf[:], raw)
			result := a.ErrBlocked
			switch kind {
			case "prepare":
				h.Binding.Prepare = id(t)
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "expired":
				o.mu.Lock()
				o.armedAt = time.Now().Add(-11 * time.Second)
				o.mu.Unlock()
			case "success":
				result = nil
			case "conflict":
				result = a.ErrConflict
			case "duplicate":
				_ = o.Context(context.Background())
			case "closed":
				o.Close()
			}
			var sealed cc.Status
			var sealErr error
			var done chan struct{}
			if kind == "finalize-race" {
				done = make(chan struct{})
				go func() { sealed, sealErr = o.Finalize(q); close(done) }()
			}
			consumerFrom(ctx).authentication(ctx, h, leaf, a.ID(q.WorkerScope.StoreUUID), a.ID(q.WorkerScope.ServiceEpoch), result)
			o.Finish(ctx, result)
			if kind == "duplicate-finalize-race" {
				done = make(chan struct{})
				go func() { sealed, sealErr = o.Finalize(q); close(done) }()
				other := o.Context(context.Background())
				o.Finish(other, context.Canceled)
			}
			if done != nil {
				<-done
			}
			s, err := o.Query(q)
			must(t, err)
			must(t, cc.ValidateStatus(s))
			if done != nil && sealErr == nil {
				must(t, cc.ValidateStatus(sealed))
				if s.State != "finalized" || *s.Evidence.Hello != *sealed.Evidence.Hello {
					t.Fatal("race changed seal", s)
				}
				sealed.Evidence.Hello.Binding.Key = "mutated"
				again, err := o.Finalize(q)
				must(t, err)
				if *again.Evidence.Hello != h {
					t.Fatal("race aliased snapshot")
				}
			}
			if kind == "exact" || kind == "finalize-race" || (kind == "duplicate-finalize-race" && sealErr == nil) {
				if s.State != "observed" && s.State != "finalized" {
					t.Fatal(s)
				}
				bad := s
				evidence := *s.Evidence
				bad.Evidence = &evidence
				hello := *evidence.Hello
				hello.Binding.Prepare = id(t)
				evidence.Hello = &hello
				if cc.ValidateStatus(bad) == nil {
					t.Fatal("partial Hello equality")
				}
				_, err = o.Finalize(q)
				must(t, err)
			} else {
				if s.Evidence != nil || s.State == "observed" {
					t.Fatal("false proof", s)
				}
				if _, err = o.Finalize(q); err == nil {
					t.Fatal("sealed false proof")
				}
			}
		})
	}
}
