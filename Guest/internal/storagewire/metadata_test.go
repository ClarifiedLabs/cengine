package storagewire

import (
	"encoding/json"
	"math"
	"testing"
)

func TestMetadataABI3Shapes(t *testing.T) {
	fh := HandleID(2)
	for _, tc := range []struct {
		name  string
		b     SetAttrRequest
		valid bool
	}{
		{"missing", SetAttrRequest{Node: 1}, false},
		{"unknown", SetAttrRequest{Node: 1, Semantics: MetadataValid | 1024}, false},
		{"no_valid", SetAttrRequest{Node: 1, Semantics: MetadataCTime}, false},
		{"chown_minus_one", SetAttrRequest{Node: 1, Semantics: MetadataValid | MetadataCTime | MetadataKillSUID | MetadataKillSGID | MetadataKillPriv}, true},
		{"standalone_force_kill", SetAttrRequest{Node: 1, Semantics: MetadataValid | MetadataForce | MetadataKillSUID | MetadataKillSGID | MetadataKillPriv}, true},
		{"mode_kill", SetAttrRequest{Node: 1, Valid: SetMode, Semantics: MetadataValid | MetadataKillSGID}, false},
		{"mode_priv", SetAttrRequest{Node: 1, Valid: SetMode, Semantics: MetadataValid | MetadataKillPriv}, true},
		{"force_mode", SetAttrRequest{Node: 1, Valid: SetMode, Semantics: MetadataValid | MetadataForce}, false},
		{"force_uid", SetAttrRequest{Node: 1, Valid: SetUID, Semantics: MetadataValid | MetadataForce}, false},
		{"force_gid", SetAttrRequest{Node: 1, Valid: SetGID, Semantics: MetadataValid | MetadataForce}, false},
		{"force_explicit_time", SetAttrRequest{Node: 1, Valid: SetATime, Semantics: MetadataValid | MetadataForce}, false},
		{"force_explicit_mtime", SetAttrRequest{Node: 1, Valid: SetMTime, Semantics: MetadataValid | MetadataForce}, false},
		{"force_times_set", SetAttrRequest{Node: 1, Semantics: MetadataValid | MetadataForce | MetadataTimesSet}, false},
		{"force_touch", SetAttrRequest{Node: 1, Semantics: MetadataValid | MetadataForce | MetadataTouch}, false},
		{"force_now", SetAttrRequest{Node: 1, Valid: SetATime | SetATimeNow | SetMTime | SetMTimeNow, ATime: Timestamp{-9, 2}, MTime: Timestamp{7, 3}, Semantics: MetadataValid | MetadataForce}, true},
		{"explicit", SetAttrRequest{Node: 1, Valid: SetATime | SetMTime, ATime: Timestamp{-9, 2}, Semantics: MetadataValid | MetadataTimesSet}, true},
		{"touch", SetAttrRequest{Node: 1, Valid: SetATime | SetATimeNow | SetMTime | SetMTimeNow, Semantics: MetadataValid | MetadataTouch}, true},
		{"now_missing_time", SetAttrRequest{Node: 1, Valid: SetMTimeNow, Semantics: MetadataValid}, false},
		{"open_size_missing", SetAttrRequest{Node: 1, Semantics: MetadataValid | MetadataOpen}, false},
		{"open_size_nonzero", SetAttrRequest{Node: 1, Valid: SetSize, Size: 1, Semantics: MetadataValid | MetadataOpen}, false},
		{"open", SetAttrRequest{Node: 1, Valid: SetSize, Semantics: MetadataValid | MetadataOpen}, true},
		{"file_missing_handle", SetAttrRequest{Node: 1, Semantics: MetadataValid | MetadataFile}, false},
		{"file", SetAttrRequest{Node: 1, Handle: &fh, Semantics: MetadataValid | MetadataFile}, true},
		{"uid_minus_one_field", SetAttrRequest{Node: 1, Valid: SetUID, UID: math.MaxUint32, Semantics: MetadataValid}, false},
		{"gid_minus_one_field", SetAttrRequest{Node: 1, Valid: SetGID, GID: math.MaxUint32, Semantics: MetadataValid}, false},
		{"legacy", SetAttrRequest{Node: 1, Valid: SetSize | SetKillSUIDGID, KillSUIDGID: true, Semantics: MetadataValid | MetadataKillSUID}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := request(tc.b)
			if err := r.Validate(); (err == nil) != tc.valid {
				t.Fatalf("Validate: %v", err)
			}
			if _, err := Marshal(&r); (err == nil) != tc.valid {
				t.Fatalf("Marshal: %v", err)
			}
			body, _ := json.Marshal(tc.b)
			raw, _ := json.Marshal(requestEnvelope{r.Sequence, r.Auth, OpSetAttr, body})
			var out Request
			if err := Unmarshal(raw, &out); (err == nil) != tc.valid {
				t.Fatalf("Unmarshal: %v", err)
			}
		})
	}
}

func TestFrozenMetadataNamesAndProfile(t *testing.T) {
	bits := []MetadataSemantics{MetadataValid, MetadataKillSUID, MetadataKillSGID, MetadataKillPriv, MetadataForce, MetadataCTime, MetadataTimesSet, MetadataTouch, MetadataFile, MetadataOpen}
	for i, b := range bits {
		if b != 1<<i {
			t.Fatal(i, b)
		}
	}
	p := RequiredProfile()
	if MetadataMask != 1023 || CredentialABI != 3 || p.HandleKillpriv || p.HandleKillprivV2 || p.AtomicOTrunc {
		t.Fatal(p)
	}
}

func TestMetadataFieldIsRequiredAndSetattrOnly(t *testing.T) {
	for _, setattr := range []bool{false, true} {
		var b RequestBody = GetAttrRequest{Node: 1}
		if setattr {
			b = SetAttrRequest{Node: 1, Semantics: MetadataValid}
		}
		req := request(b)
		raw, err := Marshal(&req)
		if err != nil {
			t.Fatal(err)
		}
		var obj map[string]json.RawMessage
		if err = json.Unmarshal(raw, &obj); err != nil {
			t.Fatal(err)
		}
		var body map[string]json.RawMessage
		if err = json.Unmarshal(obj["body"], &body); err != nil {
			t.Fatal(err)
		}
		if setattr {
			delete(body, "semantics")
		} else {
			body["semantics"] = json.RawMessage(`1`)
		}
		obj["body"], _ = json.Marshal(body)
		raw, _ = json.Marshal(obj)
		var dst Request
		if err = Unmarshal(raw, &dst); err == nil {
			t.Fatalf("accepted missing/nonSETATTR semantics: %s", raw)
		}
	}
}
