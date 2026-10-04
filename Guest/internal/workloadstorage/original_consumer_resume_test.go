package workloadstorage

import (
	"encoding/json"
	"reflect"
	"testing"

	cc "dev.cengine/guest/internal/consumercompat"
	p "dev.cengine/guest/internal/storagepki"
	w "dev.cengine/guest/internal/storagewire"
)

// Real Session observer + retained TLS Client/FIFO. Mount attestation and the
// DATA server are host fixtures; this is not signed shim, ROOT or native proof.
func TestOriginalResumeRetainsGuestOwnerAndBudget(t *testing.T) {
	if !originalConsumerEnabled() {
		t.Skip("exclusive full profile")
	}
	for _, fault := range []string{"valid", "unarmed", "begun", "released", "stopped", "unmounted", "detached", "replaced", "identity", "binding", "wrong-case"} {
		t.Run(fault, func(t *testing.T) {
			name := cc.SameE
			if fault == "wrong-case" {
				name = "delayed-registration"
			}
			s, arm, f, client, requests, _ := sameEClientSession(t, name, false, true)
			raw, _ := json.Marshal(arm)
			var armed OriginalConsumerEvidence
			if fault != "unarmed" {
				data, err := s.originalConsumerControl("original-consumer-arm", raw)
				if err != nil || originalDecode(data, &armed) != nil {
					t.Fatal("arm", err)
				}
				<-requests
			}
			entry := s.entries[arm.TargetAttachment]
			switch fault {
			case "begun":
				if _, err := s.originalConsumerControl("original-consumer-begin", raw); err != nil {
					t.Fatal(err)
				}
			case "released":
				if _, err := s.originalConsumerControl("original-consumer-release", raw); err != nil {
					t.Fatal(err)
				}
			case "stopped":
				s.stopped = true
			case "unmounted":
				entry.mounted = false
			case "detached":
				close(entry.attachment.(*originalClientAttachment).done)
			case "replaced":
				entry.attachment = &originalClientAttachment{sessionAttachmentFake: sessionAttachmentFake{done: make(chan struct{})}, client: client}
			case "identity":
				entry.identity = p.Identity{}
			case "binding":
				arm.Binding.GuestBootNonce = arm.Scope.Store
				raw, _ = json.Marshal(arm)
			}
			data, err := s.originalConsumerControl("original-consumer-resume", raw)
			if fault != "valid" {
				if err == nil || !f.observer.stopped {
					t.Fatal("stale/replaced/begun owner resumed", fault)
				}
				return
			}
			var resumed OriginalConsumerEvidence
			if err != nil || originalDecode(data, &resumed) != nil || !reflect.DeepEqual(resumed, armed) {
				t.Fatal("not retained Arm", err)
			}
			if f.observer.begun || f.observer.timer != nil || f.observer.ctx != nil || f.observer.probed {
				t.Fatal("resume started a lease or operation")
			}
			// Repeated unbegun observation cannot mint a new owner or consume DATA FIFO.
			data, err = s.originalConsumerControl("original-consumer-resume", raw)
			if err != nil || originalDecode(data, &resumed) != nil || !reflect.DeepEqual(resumed, armed) {
				t.Fatal("resume changed owner", err)
			}
			select {
			case <-requests:
				t.Fatal("resume fabricated a fresh DATA operation")
			default:
			}
			if _, err = s.originalConsumerControl("original-consumer-begin", raw); err != nil {
				t.Fatal(err)
			}
			deadline, ok := f.observer.ctx.Deadline()
			if !ok {
				t.Fatal("Begin budget missing")
			}
			data, err = s.originalConsumerControl("original-consumer-positive", raw)
			var positive OriginalConsumerEvidence
			if err != nil || originalDecode(data, &positive) != nil {
				t.Fatal("fresh original operation", err)
			}
			request := <-requests
			getattr, ok := request.Body.(w.GetAttrRequest)
			if !ok || getattr.Handle != nil || request.Auth.Kind != w.NodeMetadataAuth || uint64(getattr.Node) != armed.RootRequest.Node || request.Sequence <= armed.RootRequest.RequestSequence || positive.RootRequest.RequestSequence != request.Sequence || positive.OriginalOperation != (OriginalOperation{Kind: "data-getattr-root", Sequence: 2, ErrorClass: "ok"}) {
				t.Fatal("not original same-client FIFO positive")
			}
			after, _ := f.observer.ctx.Deadline()
			if after != deadline {
				t.Fatal("budget renewed")
			}
			data, err = s.originalConsumerControl("original-consumer-release", raw)
			var released struct {
				Arm   OriginalConsumerArm `json:"arm"`
				Stage string              `json:"stage"`
			}
			if err != nil || originalDecode(data, &released) != nil || released.Arm != arm || released.Stage != "released" || !f.observer.stopped || f.observer.file != nil || f.observer.attachment != nil {
				t.Fatal("release did not join exact observer", err)
			}
			select {
			case <-f.observer.done:
			default:
				t.Fatal("DATA operation not joined")
			}
		})
	}
}
