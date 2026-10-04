package workloadstorage

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	pc "dev.cengine/guest/internal/preparecompat"
)

func TestFullActualSessionProfileGate(t *testing.T) {
	h, workload, arm := compatibilityHarness(t)
	arm.Version = 3
	arm.Profile = pc.FullProfile
	reply := h.exchange("prepare-compatibility-arm", Payload{CompatibilityArm: &arm})
	if pc.CurrentProfile() != pc.FullProfile {
		if reply.Data.Code == nil || h.finish() == nil {
			t.Fatal("wrong profile accepted v3")
		}
		return
	}
	if reply.Data.CompatibilityDigest == nil {
		t.Fatal("arm ack")
	}
	o := compatibilityTestObservation(t, arm)
	o.Version = 3
	o.Profile = pc.FullProfile
	workload.observation = &o
	h.success("mount-phase", Payload{Role: ptr("prepare")})
	sendCompatibilityPrepare(t, h)
	checkpoint, err := ReadFrame(h.client)
	if err != nil || checkpoint.Operation != "prepare-checkpoint" || checkpoint.Data.CompatibilityObservation == nil || *checkpoint.Data.CompatibilityObservation != o {
		t.Fatal("physical checkpoint", err)
	}
	reply, err = ReadFrame(h.client)
	if err != nil || reply.Data.Code != nil || reply.Data.Succeeded == nil || !*reply.Data.Succeeded {
		t.Fatal("normal success", err)
	}
	h.success("close-phase", Payload{Role: ptr("prepare")})
}
func TestFullWorkloadPhysicalAndEarlyWireVectors(t *testing.T) {
	raw, err := os.ReadFile("../preparecompat/testdata/full-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Name                string
		Arm                 pc.Arm
		Observation         json.RawMessage
		PhysicalObservation *pc.Observation
	}
	if json.Unmarshal(raw, &vectors) != nil {
		t.Fatal("vectors")
	}
	for _, v := range vectors {
		var data Payload
		operation := "prepare-checkpoint"
		switch v.Name {
		case "normal", "first-child-published":
			o, err := pc.DecodeObservation(v.Observation)
			if err != nil {
				t.Fatal(err)
			}
			data.CompatibilityObservation = &o
		case "before-prepare-send", "guest-accepted-before-prepare", "data-partial-frame":
			o, err := pc.DecodeEarlyObservation(v.Observation)
			if err != nil {
				t.Fatal(err)
			}
			data.CompatibilityEarlyObservation = &o
			operation = "prepare-early-checkpoint"
		case "drain-durable-reply-lost":
			if v.PhysicalObservation == nil {
				t.Fatal("A8 missing physical vector")
			}
			data.CompatibilityObservation = v.PhysicalObservation
		default:
			continue
		}
		frame := NewFrame(operation, BootBinding(v.Arm.Binding), Scope(v.Arm.Scope), data)
		var encoded bytes.Buffer
		if err := WriteFrame(&encoded, frame); err != nil {
			t.Fatal(v.Name, err)
		}
		got, err := ReadFrame(&encoded)
		if err != nil || got.Sequence != nil || got.Kind != "" || got.Operation != operation {
			t.Fatal("checkpoint framing", err)
		}
	}
}
