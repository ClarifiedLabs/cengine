package preparecompat

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestStorageWorkerWaitClosedContract(t *testing.T) {
	for _, stage := range []string{"admitted-queued", "full-frame-before-admit"} {
		t.Run(stage, func(t *testing.T) { testStorageWorkerWaitClosedContract(t, stage) })
	}
}
func testStorageWorkerWaitClosedContract(t *testing.T, stage string) {
	t.Helper()
	arm := fullStorageArm(t, stage)
	q, err := StorageQueryForArm(arm)
	if err != nil {
		t.Fatal(err)
	}
	w := StorageWorkerWait{Query: q, Stage: stage, Token: strings.Repeat("e", 64), RequestSequence: ^uint64(0), WorkerPID: 1<<31 - 1, ExitCode: 74, Reaped: true}
	raw, err := CanonicalJSON(w)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeStorageWorkerWait(raw)
	if err != nil || got != w || ValidateStorageWorkerWaitForArm(w, arm) != nil {
		t.Fatal(got, err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	for key := range fields {
		copy := map[string]json.RawMessage{}
		for k, v := range fields {
			if k != key {
				copy[k] = v
			}
		}
		bad, _ := json.Marshal(copy)
		if _, err := DecodeStorageWorkerWait(bad); err == nil {
			t.Fatal("missing", key)
		}
	}
	for _, bad := range [][]byte{
		append(append([]byte{}, raw...), raw...), bytes.Replace(raw, []byte(`"reaped":true`), []byte(`"reaped":null`), 1),
		bytes.Replace(raw, []byte(`"exitCode":74`), []byte(`"exitCode":74,"exitCode":74`), 1),
		bytes.Replace(raw, []byte(`"exitCode":74`), []byte(`"exitCode":7.4e1`), 1),
		bytes.Replace(raw, []byte(`"exitCode":74`), []byte(`"exitCode":74,"pid":42`), 1),
		bytes.Replace(raw, []byte(`"exitCode":74`), []byte(`"exitCode":4294967296`), 1),
	} {
		if _, err := DecodeStorageWorkerWait(bad); err == nil {
			t.Fatal("open codec", string(bad))
		}
	}
	for name, mutate := range map[string]func(*StorageWorkerWait){
		"stage":          func(w *StorageWorkerWait) { w.Stage = "normal" },
		"token": func(w *StorageWorkerWait) { w.Token = "bad" }, "sequence": func(w *StorageWorkerWait) { w.RequestSequence = 0 },
		"pid-zero": func(w *StorageWorkerWait) { w.WorkerPID = 0 }, "pid-one": func(w *StorageWorkerWait) { w.WorkerPID = 1 },
		"pid-overflow": func(w *StorageWorkerWait) { w.WorkerPID = 1 << 31 }, "exit": func(w *StorageWorkerWait) { w.ExitCode = 0 },
		"unreaped": func(w *StorageWorkerWait) { w.Reaped = false }, "old-profile": func(w *StorageWorkerWait) { w.Query.Profile = Profile },
	} {
		t.Run(name, func(t *testing.T) {
			bad := w
			mutate(&bad)
			if ValidateStorageWorkerWait(bad) == nil {
				t.Fatal("accepted")
			}
		})
	}
	for _, mutate := range []func(*StorageWorkerWait){func(w *StorageWorkerWait) { w.Query.WorkerUUID = arm.Arm.RequestID }, func(w *StorageWorkerWait) { w.Query.ArmDigest = strings.Repeat("f", 64) }, func(w *StorageWorkerWait) { w.Query.RequestID = arm.WorkerUUID }} {
		bad := w
		mutate(&bad)
		if ValidateStorageWorkerWaitForArm(bad, arm) == nil {
			t.Fatal("binding mismatch")
		}
	}
}
