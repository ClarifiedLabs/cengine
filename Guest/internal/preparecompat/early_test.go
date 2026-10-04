package preparecompat

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func earlyArm(t *testing.T, name string) Arm {
	a := vectorArm(t)
	a.Version, a.Profile, a.CaseName = 2, EarlyProfile, name
	return a
}
func TestEarlyInteropVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/early-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Name                                    string
		Arm                                     json.RawMessage
		Canonical, SHA256                       string
		Observation                             json.RawMessage
		ObservationCanonical, ObservationSHA256 string
	}
	if err = json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) != 4 {
		t.Fatal("four cases required")
	}
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			arm, err := DecodeArm(v.Arm)
			if err != nil {
				t.Fatal(err)
			}
			canonical, err := CanonicalArmData(arm)
			if err != nil || string(canonical) != v.Canonical {
				t.Fatal("arm canonical", err)
			}
			digest, err := ArmDigest(arm)
			if err != nil || digest != v.SHA256 {
				t.Fatal("arm digest", err)
			}
			var o any
			if v.Name == "normal" {
				o, err = DecodeObservation(v.Observation)
			} else {
				o, err = DecodeEarlyObservation(v.Observation)
			}
			if err != nil {
				t.Fatal(err)
			}
			canonical, err = CanonicalJSON(o)
			if err != nil || string(canonical) != v.ObservationCanonical {
				t.Fatal("observation canonical", err)
			}
			sum := sha256.Sum256(canonical)
			if hex.EncodeToString(sum[:]) != v.ObservationSHA256 {
				t.Fatal("observation digest")
			}
		})
	}
}
func TestEarlyProfileClosedAndBuildIsolated(t *testing.T) {
	for _, name := range []string{"normal", "before-prepare-send", "guest-accepted-before-prepare", "data-partial-frame"} {
		a := earlyArm(t, name)
		if ValidateArm(a) != nil {
			t.Fatal(name)
		}
		witness, err := NewWitness(a)
		if (err == nil) != EarlyEnabled() || (witness != nil) != EarlyEnabled() {
			t.Fatal("build accepted wrong profile", name)
		}
		a.Version, a.Profile = 1, Profile
		if name != "normal" && ValidateArm(a) == nil {
			t.Fatal("v1 broadened", name)
		}
	}
	a := earlyArm(t, "first-child-published")
	if ValidateArm(a) == nil {
		t.Fatal("v2 A7")
	}
	for _, mutate := range []func(*Arm){func(a *Arm) { a.Version = 1 }, func(a *Arm) { a.Profile = Profile }, func(a *Arm) { a.Version = 3 }} {
		a := earlyArm(t, "normal")
		mutate(&a)
		if ValidateArm(a) == nil {
			t.Fatal("mixed profile")
		}
	}
}
func TestEarlyObservationClosedRequiredCounters(t *testing.T) {
	a := earlyArm(t, "before-prepare-send")
	digest, _ := ArmDigest(a)
	o := EarlyObservation{Version: 2, Profile: EarlyProfile, RequestID: a.RequestID, ArmDigest: digest, Stage: a.CaseName, Count: 1, TargetAttachment: a.TargetAttachment, RequestSequence: 7}
	raw, _ := CanonicalJSON(o)
	if _, err := DecodeEarlyObservation(raw); err != nil {
		t.Fatal(err)
	}
	for _, replacement := range []string{"", `"dataBytesWritten":null,`, `"dataBytesWritten":1,`, `"dataBytesWritten":0.0,`, `"dataBytesWritten":0,"dataBytesWritten":0,`, `"dataBytesWritten":0,"root":{},`} {
		bad := bytes.Replace(raw, []byte(`"dataBytesWritten":0,`), []byte(replacement), 1)
		if _, err := DecodeEarlyObservation(bad); err == nil {
			t.Fatal("accepted malformed counters", replacement)
		}
	}
	for _, mutate := range []func(*EarlyObservation){func(o *EarlyObservation) { o.Version = 1 }, func(o *EarlyObservation) { o.Profile = Profile }, func(o *EarlyObservation) { o.RequestSequence = 0 }, func(o *EarlyObservation) { o.Count = 2 }, func(o *EarlyObservation) { o.PrepareCommandsAccepted = 1 }, func(o *EarlyObservation) { o.Stage = "first-child-published" }} {
		bad := o
		mutate(&bad)
		if ValidateEarlyObservation(bad) == nil {
			t.Fatal("accepted mutation")
		}
	}
	if _, err := DecodeObservation(raw); err == nil {
		t.Fatal("early faked physical")
	}
}
