package workloadstorage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func TestOriginalConsumerPhase6RequiredOperationShape(t *testing.T) {
	for _, name := range []string{"cross-e-existing-data", "cross-e-retained-fd", "cross-e-old-leaf-reconnect"} {
		arm := originalTestArm()
		arm.CaseName = name
		if !arm.valid() {
			t.Fatalf("missing original case %s", name)
		}
	}
	evidence := OriginalConsumerEvidence{Arm: originalTestArm()}
	raw, _ := json.Marshal(evidence)
	var decoded OriginalConsumerEvidence
	if originalDecode(raw, &decoded) != nil || decoded != evidence {
		t.Fatal("exact 16-field evidence shape")
	}
	for _, bad := range [][]byte{
		bytes.Replace(raw, []byte(`,"originalOperation":{"kind":"","sequence":0,"errorClass":""}`), nil, 1),
		bytes.Replace(raw, []byte(`"originalOperation"`), []byte(`"OriginalOperation"`), 1),
		bytes.Replace(raw, []byte(`"errorClass":""`), []byte(`"errorClass":"","errorClass":""`), 1),
		bytes.Replace(raw, []byte(`"sequence":0`), []byte(`"sequence":null`), 1),
	} {
		if originalDecode(bad, &decoded) == nil {
			t.Fatal("open operation evidence schema")
		}
	}
}

// These private attachments test refusal gates only. No simulated FD errno or
// mock connection can create accepted DATA/FD/TLS denial evidence here.
type originalRefusalAttachment struct {
	sessionAttachmentFake
	reason error
}

func (a *originalRefusalAttachment) Err() error { return a.reason }

func TestOriginalConsumerPhase6RefusesFalseLocalNegatives(t *testing.T) {
	for _, name := range []string{"unjoined", "clean-join", "successful-fsync", "closed-fd", "not-original-client"} {
		t.Run(name, func(t *testing.T) {
			_, _, _, scope, peer := originalIdentities(t)
			arm := originalTestArm()
			arm.CaseName = "cross-e-retained-fd"
			file, err := os.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			if err := file.Sync(); err != nil {
				t.Fatal("positive real directory fsync", err)
			}
			attachment := &originalRefusalAttachment{sessionAttachmentFake: sessionAttachmentFake{done: make(chan struct{})}, reason: errors.New("terminal")}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch name {
			case "unjoined":
				cancel()
			case "clean-join":
				attachment.reason = nil
				close(attachment.done)
			case "closed-fd":
				file.Close()
				close(attachment.done)
			case "not-original-client":
				arm.CaseName = "cross-e-existing-data"
				close(attachment.done)
			default:
				close(attachment.done)
			}
			o := &originalConsumer{arm: arm, peer: peer, attachment: attachment, file: file, ctx: ctx, begun: true}
			result, err := o.probe(OriginalConsumerProbe{Arm: arm, Scope: scope, Peer: peer})
			if err == nil || result.OriginalOperation != (OriginalOperation{}) || result.SignCount != 0 || result.LocalError != "" || o.capture != nil {
				t.Fatal("false local rejection/TLS evidence", result, err)
			}
		})
	}
}

func TestOriginalConsumerPhase8VersionAndMissingActualDataRefused(t *testing.T) {
	arm := originalTestArm()
	arm.Version = 3
	arm.CaseName = "cross-e-existing-data"
	if !arm.valid() {
		t.Fatal("matching DATA version rejected")
	}
	for _, name := range []string{"cross-e-old-leaf-reconnect", "cross-e-retained-fd", "same-e-existing-data", "issued-identity-wrong-volume"} {
		bad := arm
		bad.CaseName = name
		if bad.valid() {
			t.Fatal("version3 widened", name)
		}
	}
	if !originalConsumerEnabled() {
		return
	}
	s, arm, _ := originalInstalledSession(t)
	arm.Version = 3
	arm.CaseName = "cross-e-existing-data"
	raw, _ := json.Marshal(arm)
	if _, err := s.originalConsumerControl("original-consumer-arm", raw); err == nil {
		t.Fatal("FD positive stood in for actual DATA positive")
	}
}
