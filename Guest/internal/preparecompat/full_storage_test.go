package preparecompat

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	a "dev.cengine/guest/internal/storageauthority"
)

func fullArm(t *testing.T, name string) Arm {
	t.Helper()
	arm := vectorArm(t)
	arm.Version = 3
	arm.Profile = FullProfile
	arm.CaseName = name
	return arm
}
func fullStorageArm(t *testing.T, name string) StorageArm {
	t.Helper()
	arm := fullArm(t, name)
	return StorageArm{Arm: arm, WorkerUUID: arm.Binding.GuestBootNonce}
}
func fullStorageObservation(t *testing.T, s StorageArm) StorageObservation {
	t.Helper()
	q, err := StorageQueryForArm(s)
	if err != nil {
		t.Fatal(err)
	}
	o := StorageObservation{Version: 3, Profile: FullProfile, RequestID: q.RequestID, ArmDigest: q.ArmDigest, WorkerUUID: q.WorkerUUID, Stage: s.Arm.CaseName, Count: 1, TargetAttachment: s.Arm.TargetAttachment}
	var slot Slot
	var credential Credential
	for _, v := range s.Arm.Slots {
		if v.Attachment == s.Arm.TargetAttachment {
			slot = v
		}
	}
	for _, v := range s.Arm.Credentials {
		if v.Attachment == s.Arm.TargetAttachment {
			credential = v
		}
	}
	scope := s.Arm.Scope
	binding := a.Binding{Store: a.ID(scope.Store), Volume: a.ID(slot.Volume), Attachment: a.ID(slot.Attachment), Prepare: a.ID(scope.Prepare), Container: a.ContainerID(scope.Container), Launch: a.ID(scope.Launch), Key: a.Fingerprint(credential.Key), Role: a.PrepareRole, Mode: a.ReadWrite}
	switch s.Arm.CaseName {
	case "full-frame-before-admit", "admitted-queued":
		o.Admission = &AdmissionCut{RequestSequence: 42, Admitted: s.Arm.CaseName == "admitted-queued", ReleaseToken: strings.Repeat("e", 64)}
	case "transaction-published-bind-reply-lost":
		o.Bound = &BoundCut{RequestSequence: 43, Intent: a.CopyIntent{ID: a.ID(scope.Intent), Owner: binding, Epoch: a.ID(scope.ServiceEpoch), Root: a.CopyRootV1{Store: binding.Store, Volume: binding.Volume, BackingUUID: [16]byte{1}, Root: object(1, 16384)}, Transaction: object(2, 16384), Phase: a.CopyBound, InitialCaptured: true, Initial: a.CopyCleanupV1{UID: 501, GID: 20, Mode: 0755, ATimeSeconds: -9223372036854775808, MTimeSeconds: 9223372036854775807, ATimeNanos: 1, MTimeNanos: 999999999}}}
	case "drain-durable-reply-lost":
		o.Drain = &DrainCut{RetireOperation: scope.Intent, Receipt: a.Receipt{Schema: a.SchemaVersion, Store: binding.Store, Volume: binding.Volume, Attachment: binding.Attachment, Launch: binding.Launch, Prepare: binding.Prepare, Revision: 18446744073709551615}}
	}
	return o
}
func TestFullStorageCanonicalProjectionAndScope(t *testing.T) {
	for _, name := range []string{"full-frame-before-admit", "admitted-queued", "transaction-published-bind-reply-lost", "drain-durable-reply-lost"} {
		t.Run(name, func(t *testing.T) {
			arm := fullStorageArm(t, name)
			o := fullStorageObservation(t, arm)
			if ValidateStorageObservationForArm(o, arm) != nil {
				t.Fatal("observation binding")
			}
			b, err := CanonicalJSON(o)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := DecodeStorageObservation(b)
			if err != nil || !reflect.DeepEqual(decoded, o) {
				t.Fatal("observation roundtrip", err, string(b))
			}
			if o.Bound != nil {
				if !bytes.Contains(b, []byte(`"atime_seconds":"-9223372036854775808"`)) || !bytes.Contains(b, []byte(`"backing_uuid":"01000000000000000000000000000000"`)) || !bytes.Contains(b, []byte(`"manifest_digest":"`+strings.Repeat("0", 64)+`"`)) {
					t.Fatal("not exact projection", string(b))
				}
			}
			bad := arm
			bad.WorkerUUID = arm.Arm.RequestID
			if ValidateStorageObservationForArm(o, bad) == nil {
				t.Fatal("worker mismatch")
			}
			bad = arm
			bad.Arm.Credentials = append([]Credential{}, arm.Arm.Credentials...)
			bad.Arm.Credentials[0].Key = strings.Repeat("9", 64)
			if ValidateStorageObservationForArm(o, bad) == nil {
				t.Fatal("key/digest mismatch")
			}
			q, _ := StorageQueryForArm(arm)
			status := StorageStatus{Query: q, State: "observed", Observation: &o}
			if ValidateStorageStatusForArm(status, arm) != nil {
				t.Fatal("status")
			}
			b, _ = CanonicalJSON(status)
			if _, err := DecodeStorageStatus(b); err != nil {
				t.Fatal("status decode", err)
			}
		})
	}
}
func TestFullStorageStrictShapesAndSignedStrings(t *testing.T) {
	arm := fullStorageArm(t, "transaction-published-bind-reply-lost")
	o := fullStorageObservation(t, arm)
	raw, _ := CanonicalJSON(o)
	for name, bad := range map[string][]byte{
		"null":               bytes.Replace(raw, []byte(`"bound":{`), []byte(`"bound":null,"unused":{`), 1),
		"missing-initial":    bytes.Replace(raw, []byte(`"initial_captured":true,`), nil, 1),
		"uppercase-field":    bytes.Replace(raw, []byte(`"manifest_size":0`), []byte(`"ManifestSize":0`), 1),
		"unknown":            bytes.Replace(raw, []byte(`"requestSequence":43`), []byte(`"requestSequence":43,"extra":0`), 1),
		"duplicate":          bytes.Replace(raw, []byte(`"requestSequence":43`), []byte(`"requestSequence":43,"requestSequence":43`), 1),
		"numeric-seconds":    bytes.Replace(raw, []byte(`"-9223372036854775808"`), []byte(`-9223372036854775808`), 1),
		"seconds-overflow":   bytes.Replace(raw, []byte(`"-9223372036854775808"`), []byte(`"-9223372036854775809"`), 1),
		"seconds-minus-zero": bytes.Replace(raw, []byte(`"-9223372036854775808"`), []byte(`"-0"`), 1),
		"seconds-plus":       bytes.Replace(raw, []byte(`"-9223372036854775808"`), []byte(`"+1"`), 1),
		"byte-array":         bytes.Replace(raw, []byte(`"backing_uuid":"01000000000000000000000000000000"`), []byte(`"backing_uuid":[1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]`), 1),
		"sealed":             bytes.Replace(raw, []byte(`"phase":"BOUND"`), []byte(`"phase":"SEALED"`), 1),
		"manifest-size":      bytes.Replace(raw, []byte(`"manifest_size":0`), []byte(`"manifest_size":1`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if bytes.Equal(raw, bad) {
				t.Fatal("mutation failed")
			}
			if _, err := DecodeStorageObservation(bad); err == nil {
				t.Fatal("invalid accepted")
			}
		})
	}
	o.Admission = &AdmissionCut{RequestSequence: 1, ReleaseToken: strings.Repeat("1", 64)}
	if ValidateStorageObservation(o) == nil {
		t.Fatal("multiple cuts")
	}
}
func TestFullStorageStateAndRelease(t *testing.T) {
	for _, name := range []string{"full-frame-before-admit", "admitted-queued", "transaction-published-bind-reply-lost", "drain-durable-reply-lost"} {
		arm := fullStorageArm(t, name)
		q, _ := StorageQueryForArm(arm)
		o := fullStorageObservation(t, arm)
		if ValidateStorageStatus(StorageStatus{Query: q, State: "armed"}) != nil {
			t.Fatal("armed")
		}
		if ValidateStorageStatus(StorageStatus{Query: q, State: "armed", Observation: &o}) == nil {
			t.Fatal("armed observation")
		}
		if ValidateStorageStatus(StorageStatus{Query: q, State: "observed"}) == nil {
			t.Fatal("observed missing")
		}
		status := StorageStatus{Query: q, State: "released", Observation: &o}
		release := StorageRelease{Query: q, Stage: name, Token: strings.Repeat("e", 64)}
		released := name == "full-frame-before-admit" || name == "admitted-queued"
		if (ValidateStorageStatus(status) == nil) != released || (ValidateStorageRelease(release) == nil) != released {
			t.Fatal("release case", name)
		}
		status.State = "observed"
		status.RetirementStarted = true
		if name == "admitted-queued" {
			if ValidateStorageStatus(status) == nil {
				t.Fatal("missing pending proof")
			}
			status.AcceptedInFlight = 1
		}
		if ValidateStorageStatus(status) != nil {
			t.Fatal("real retirement status")
		}
	}
}

// Full vectors are generated by the actual Go canonical codecs, never a second
// JSON implementation. This explicit test-only update is not a live fault knob.
func TestFullInteropVectors(t *testing.T) {
	names := []string{"normal", "before-prepare-send", "guest-accepted-before-prepare", "data-partial-frame", "full-frame-before-admit", "admitted-queued", "transaction-published-bind-reply-lost", "first-child-published", "drain-durable-reply-lost"}
	type vector struct {
		StorageObservation           *StorageObservation `json:"storageObservation,omitempty"`
		StorageObservationCanonical  string              `json:"storageObservationCanonical,omitempty"`
		StorageObservationSHA256     string              `json:"storageObservationSHA256,omitempty"`
		PhysicalObservation          *Observation        `json:"physicalObservation,omitempty"`
		PhysicalObservationCanonical string              `json:"physicalObservationCanonical,omitempty"`
		PhysicalObservationSHA256    string              `json:"physicalObservationSHA256,omitempty"`
		Name                         string              `json:"name"`
		Arm                          Arm                 `json:"arm"`
		Canonical                    string              `json:"canonical"`
		SHA256                       string              `json:"sha256"`
		Observation                  any                 `json:"observation"`
		ObservationCanonical         string              `json:"observationCanonical"`
		ObservationSHA256            string              `json:"observationSHA256"`
		StorageArm                   *StorageArm         `json:"storageArm,omitempty"`
		StorageQuery                 *StorageQuery       `json:"storageQuery,omitempty"`
		StorageStatus                *StorageStatus      `json:"storageStatus,omitempty"`
		StorageRelease               *StorageRelease     `json:"storageRelease,omitempty"`
	}
	vectors := []vector{}
	for _, name := range names {
		arm := fullArm(t, name)
		canonical, err := CanonicalArmData(arm)
		if err != nil {
			t.Fatal(err)
		}
		digest, _ := ArmDigest(arm)
		v := vector{Name: name, Arm: arm, Canonical: string(canonical), SHA256: digest}
		switch {
		case storageCase(name):
			storageArm := fullStorageArm(t, name)
			o := fullStorageObservation(t, storageArm)
			q, _ := StorageQueryForArm(storageArm)
			v.StorageArm = &storageArm
			v.StorageQuery = &q
			v.StorageStatus = &StorageStatus{Query: q, State: "observed", Observation: &o}
			v.Observation = o
			v.StorageObservation = &o
			if name == "drain-durable-reply-lost" {
				physical := testObservation(t, arm)
				physical.Version = 3
				physical.Profile = FullProfile
				v.PhysicalObservation = &physical
				raw, err := CanonicalJSON(physical)
				if err != nil {
					t.Fatal(err)
				}
				v.PhysicalObservationCanonical = string(raw)
				sum := sha256.Sum256(raw)
				v.PhysicalObservationSHA256 = hex.EncodeToString(sum[:])
			}
			if o.Admission != nil {
				v.StorageRelease = &StorageRelease{Query: q, Stage: name, Token: o.Admission.ReleaseToken}
			}
		case earlyCase(name):
			o := EarlyObservation{Version: 3, Profile: FullProfile, RequestID: arm.RequestID, ArmDigest: digest, Stage: name, Count: 1, TargetAttachment: arm.TargetAttachment, RequestSequence: 42}
			if name != "before-prepare-send" {
				o.PrepareCommandsSent = 1
				o.PrepareCommandsAccepted = 1
			}
			if name == "data-partial-frame" {
				o.DataBytesWritten = 5
			}
			v.Observation = o
		default:
			o := testObservation(t, arm)
			o.Version = 3
			o.Profile = FullProfile
			v.Observation = o
		}
		ob, err := CanonicalJSON(v.Observation)
		if err != nil {
			t.Fatal(err)
		}
		v.ObservationCanonical = string(ob)
		sum := sha256.Sum256(ob)
		v.ObservationSHA256 = hex.EncodeToString(sum[:])
		if v.StorageObservation != nil {
			v.StorageObservationCanonical = v.ObservationCanonical
			v.StorageObservationSHA256 = v.ObservationSHA256
		}
		vectors = append(vectors, v)
	}
	expected, err := json.MarshalIndent(vectors, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	expected = append(expected, '\n')
	if os.Getenv("CENGINE_UPDATE_FULL_VECTORS") == "1" {
		if err := os.WriteFile("testdata/full-vectors.json", expected, 0600); err != nil {
			t.Fatal(err)
		}
	}
	actual, err := os.ReadFile("testdata/full-vectors.json")
	if err != nil || !bytes.Equal(actual, expected) {
		t.Fatal("full vectors not exact Go canonical output", err)
	}
	for _, v := range vectors {
		raw := []byte(v.ObservationCanonical)
		switch {
		case storageCase(v.Name):
			if _, err := DecodeStorageObservation(raw); err != nil {
				t.Fatal(v.Name, err)
			}
		case earlyCase(v.Name):
			if _, err := DecodeEarlyObservation(raw); err != nil {
				t.Fatal(v.Name, err)
			}
		default:
			if _, err := DecodeObservation(raw); err != nil {
				t.Fatal(v.Name, err)
			}
		}
	}
}
