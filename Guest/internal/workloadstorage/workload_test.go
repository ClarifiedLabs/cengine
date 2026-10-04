package workloadstorage

import "testing"

func TestManagedWorkloadRejectsPrivateInjectionAndAliases(t *testing.T) {
	valid := []byte(`{"id":"container","ioClaim":"","mounts":[],"arguments":["true"],"resources":{}}`)
	if _, err := decodeManagedWorkload(valid); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		`{"ioClaim":"secret","mounts":[]}`,
		`{"mounts":[]}`,
		`{"ioClaim":"","ioClaim":"","mounts":[]}`,
		`{"ioClaim":"","\u0069oClaim":"","mounts":[]}`,
		`{"ioClaim":"","mounts":[{"managedAttachment":""}]}`,
		`{"ioClaim":"","mounts":[{"managedAttachment":null}]}`,
		`{"ioClaim":"","mounts":[],"privateKey":"secret"}`,
		`{"ioClaim":"","mounts":[],"arguments":["safe"],"ARGUMENTS":["other"]}`,
		`{"ioClaim":"","mounts":[],"user":{"UID":0}}`,
		`{"ioClaim":"","mounts":[],"resources":{"MEMORYBYTES":1}}`,
		`{"ioClaim":"","mounts":[]} {}`,
		`{"ioClaim":"","mounts":[],"environment":["\ud800"]}`,
	} {
		if _, err := decodeManagedWorkload([]byte(raw)); err == nil {
			t.Fatal("invalid workload accepted")
		}
	}
}
