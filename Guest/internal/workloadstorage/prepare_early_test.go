package workloadstorage

import (
	"bytes"
	pc "dev.cengine/guest/internal/preparecompat"
	"encoding/json"
	"os"
	"testing"
)

func TestEarlyArmActualSessionProfileGate(t *testing.T) {
	h, workload, arm := compatibilityHarness(t)
	arm.Version, arm.Profile = 2, pc.EarlyProfile
	reply := h.exchange("prepare-compatibility-arm", Payload{CompatibilityArm: &arm})
	if !pc.EarlyEnabled() {
		if reply.Data.Code == nil || h.finish() == nil {
			t.Fatal("old/ordinary accepted v2")
		}
		return
	}
	digest, _ := pc.ArmDigest(arm)
	if reply.Data.CompatibilityDigest == nil || *reply.Data.CompatibilityDigest != digest {
		t.Fatal("new profile ack")
	}
	o := compatibilityTestObservation(t, arm)
	o.Version, o.Profile = 2, pc.EarlyProfile
	workload.observation = &o
	h.success("mount-phase", Payload{Role: ptr("prepare")})
	sendCompatibilityPrepare(t, h)
	event, err := ReadFrame(h.client)
	if err != nil || event.Operation != "prepare-checkpoint" || event.Data.CompatibilityObservation == nil || *event.Data.CompatibilityObservation != o {
		t.Fatal("required physical event", err)
	}
	reply, err = ReadFrame(h.client)
	if err != nil || reply.Data.Code != nil || reply.Data.Succeeded == nil || !*reply.Data.Succeeded {
		t.Fatal("normal success", err)
	}
	h.success("close-phase", Payload{Role: ptr("prepare")})
}
func TestEarlyActualWorkloadWireVectors(t *testing.T) {
	raw, err := os.ReadFile("../preparecompat/testdata/early-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Name        string
		Arm         pc.Arm
		Observation json.RawMessage
	}
	if err = json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors {
		var payload Payload
		op := "prepare-early-checkpoint"
		if v.Name == "normal" {
			o, err := pc.DecodeObservation(v.Observation)
			if err != nil {
				t.Fatal(err)
			}
			payload.CompatibilityObservation = &o
			op = "prepare-checkpoint"
		} else {
			o, err := pc.DecodeEarlyObservation(v.Observation)
			if err != nil {
				t.Fatal(err)
			}
			payload.CompatibilityEarlyObservation = &o
		}
		f := NewFrame(op, BootBinding(v.Arm.Binding), Scope(v.Arm.Scope), payload)
		var b bytes.Buffer
		if err := WriteFrame(&b, f); err != nil {
			t.Fatal(v.Name, err)
		}
		got, err := ReadFrame(&b)
		if err != nil || got.Operation != op || got.Sequence != nil || got.Kind != "" {
			t.Fatal("event discipline", err)
		}
		f.Operation = "prepare-checkpoint"
		if v.Name != "normal" && WriteFrame(&b, f) == nil {
			t.Fatal("early accepted as physical")
		}
	}
}
