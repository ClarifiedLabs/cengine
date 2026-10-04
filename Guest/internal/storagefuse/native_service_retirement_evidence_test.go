//go:build linux || darwin

package storagefuse_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"testing"

	a "dev.cengine/guest/internal/storageauthority"
)

// Mirror the closed completion certificate, not the version-2 PREPARE root-only
// retry proof. Authority.certifyRetirement writes this only AFTER the full
// retained-resource barrier succeeds, and BEFORE receipt metadata persistence.
type nativeRetirementProof struct {
	Version    int           `json:"version"`
	Attempt    a.ID          `json:"attempt"`
	Store      a.Store       `json:"store"`
	Epoch      a.ID          `json:"epoch"`
	Controller a.Controller  `json:"controller"`
	Bootstrap  a.Fingerprint `json:"bootstrap"`
	Volume     a.Volume      `json:"volume"`
	Binding    a.Binding     `json:"binding"`
	Operation  a.ID          `json:"operation"`
	Revision   uint64        `json:"revision"`
	Prior      string        `json:"prior_digest"`
	Next       string        `json:"next_digest"`
}

type nativeRetirementOperation struct {
	Kind   string `json:"kind"`
	Digest string `json:"digest"`
}

func nativeRetirementDigest(raw []byte) string { return fmt.Sprintf("%x", sha256.Sum256(raw)) }

// Check both exact images: the candidate may differ only by revision and the
// selected DRAINED receipt. Candidate bytes are NOT evidence that its fsync
// succeeded; the stage-5 injected error must still quarantine and refuse reopen.
func nativeServiceRetirementProof(raw, prior, candidate []byte, binding a.Binding, operation a.ID) error {
	var proof nativeRetirementProof
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&proof); err != nil {
		return err
	}
	canonical, err := json.Marshal(proof)
	if err != nil || len(raw) > 4096 || decoder.Decode(new(any)) != io.EOF || !bytes.Equal(raw, canonical) ||
		!regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(string(proof.Attempt)) {
		return fmt.Errorf("noncanonical retirement completion proof")
	}
	var state struct {
		Revision    uint64                             `json:"revision"`
		Store       a.Store                            `json:"store"`
		Epoch       a.ID                               `json:"epoch"`
		Controller  a.Controller                       `json:"controller"`
		Bootstrap   a.Fingerprint                      `json:"bootstrap"`
		Volumes     map[a.ID]a.Volume                  `json:"volumes"`
		Attachments map[a.ID]a.Attachment              `json:"attachments"`
		Operations  map[a.ID]nativeRetirementOperation `json:"operations"`
	}
	if err := json.Unmarshal(prior, &state); err != nil {
		return err
	}
	want := nativeRetirementProof{1, proof.Attempt, state.Store, state.Epoch, state.Controller,
		state.Bootstrap, state.Volumes[binding.Volume], binding, operation, state.Revision + 1,
		nativeRetirementDigest(prior), nativeRetirementDigest(candidate)}
	record := state.Attachments[binding.Attachment]
	request, err := json.Marshal(a.RetireRequest{Operation: operation, Store: binding.Store, Volume: binding.Volume, Attachment: binding.Attachment, Launch: binding.Launch})
	if err != nil {
		return err
	}
	if state.Operations[operation] != (nativeRetirementOperation{"retire", nativeRetirementDigest(request)}) {
		return fmt.Errorf("predecessor lacks exact retirement operation digest")
	}
	if proof != want || state.Revision == 0 || state.Revision == ^uint64(0) ||
		binding.Store != state.Store.ID || want.Volume.ID != binding.Volume ||
		record.Binding != binding || record.Retirement != operation || record.Phase != a.Retiring || record.Receipt != nil {
		return fmt.Errorf("retirement proof differs from exact RETIRING predecessor")
	}
	var before, after map[string]json.RawMessage
	if err := json.Unmarshal(prior, &before); err != nil {
		return err
	}
	if err := json.Unmarshal(candidate, &after); err != nil {
		return err
	}
	receipt := a.Receipt{Schema: a.SchemaVersion, Store: binding.Store, Volume: binding.Volume,
		Attachment: binding.Attachment, Launch: binding.Launch, Prepare: binding.Prepare, Revision: proof.Revision}
	record.Phase, record.Receipt = a.Drained, &receipt
	state.Attachments[binding.Attachment] = record
	before["attachments"], err = json.Marshal(state.Attachments)
	if err != nil {
		return err
	}
	before["revision"], err = json.Marshal(proof.Revision)
	if err != nil || !reflect.DeepEqual(before, after) {
		return fmt.Errorf("receipt candidate changed more than selected receipt/revision")
	}
	return nil
}

func TestNativeServiceRetirementProofOracle(t *testing.T) {
	id := a.ID("11111111-1111-4111-8111-111111111111")
	binding := a.Binding{Store: id, Volume: id, Attachment: id, Launch: id, Role: a.RuntimeRole, Mode: a.ReadWrite}
	marshal := func(v any) []byte {
		t.Helper()
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	record := a.Attachment{Binding: binding, Phase: a.Retiring, Retirement: id}
	state := map[string]any{"revision": 7, "store": a.Store{ID: id}, "epoch": id,
		"controller": a.Controller{Epoch: 1}, "bootstrap": "key", "volumes": map[a.ID]a.Volume{id: {ID: id}},
		"attachments": map[a.ID]a.Attachment{id: record}, "unrelated": "retained"}
	request := marshal(a.RetireRequest{Operation: id, Store: id, Volume: id, Attachment: id, Launch: id})
	state["operations"] = map[a.ID]nativeRetirementOperation{id: {"retire", nativeRetirementDigest(request)}}
	prior := marshal(state)
	record.Phase = a.Drained
	record.Receipt = &a.Receipt{Schema: a.SchemaVersion, Store: id, Volume: id, Attachment: id, Launch: id, Revision: 8}
	state["revision"], state["attachments"] = 8, map[a.ID]a.Attachment{id: record}
	candidate := marshal(state)
	proof := nativeRetirementProof{1, id, a.Store{ID: id}, id, a.Controller{Epoch: 1}, "key", a.Volume{ID: id}, binding, id, 8, nativeRetirementDigest(prior), nativeRetirementDigest(candidate)}
	if err := nativeServiceRetirementProof(marshal(proof), prior, candidate, binding, id); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*nativeRetirementProof){
		"version":    func(p *nativeRetirementProof) { p.Version = 2 },
		"attempt":    func(p *nativeRetirementProof) { p.Attempt = "not-an-attempt" },
		"store":      func(p *nativeRetirementProof) { p.Store.Root.Inode++ },
		"epoch":      func(p *nativeRetirementProof) { p.Epoch = "other" },
		"controller": func(p *nativeRetirementProof) { p.Controller.Epoch++ },
		"bootstrap":  func(p *nativeRetirementProof) { p.Bootstrap = "other" },
		"volume":     func(p *nativeRetirementProof) { p.Volume.Root.Inode++ },
		"binding":    func(p *nativeRetirementProof) { p.Binding.Launch = "other" },
		"operation":  func(p *nativeRetirementProof) { p.Operation = "other" },
		"revision":   func(p *nativeRetirementProof) { p.Revision++ },
		"prior":      func(p *nativeRetirementProof) { p.Prior = p.Next },
		"next":       func(p *nativeRetirementProof) { p.Next = p.Prior },
	} {
		t.Run(name, func(t *testing.T) {
			bad := proof
			mutate(&bad)
			if nativeServiceRetirementProof(marshal(bad), prior, candidate, binding, id) == nil {
				t.Fatal("accepted mismatched proof")
			}
		})
	}
	for name, raw := range map[string][]byte{
		"legacy-marker": []byte("Uncertain authority IO or barrier: offline repair required.\n"),
		"truncated":     marshal(proof)[:20],
		"trailing":      append(marshal(proof), '\n'),
		"second-value":  append(marshal(proof), []byte("{}")...),
		"unknown-field": append(marshal(proof)[:len(marshal(proof))-1], []byte(`,"kind":"prepare-root-only-retry"}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			if nativeServiceRetirementProof(raw, prior, candidate, binding, id) == nil {
				t.Fatal("accepted malformed/noncompletion proof")
			}
		})
	}
	for name, operation := range map[string]nativeRetirementOperation{
		"missing": {}, "wrong-kind": {"register", nativeRetirementDigest(request)}, "wrong-digest": {"retire", nativeRetirementDigest(nil)},
	} {
		t.Run("operation-"+name, func(t *testing.T) {
			var before, after map[string]json.RawMessage
			if err := json.Unmarshal(prior, &before); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(candidate, &after); err != nil {
				t.Fatal(err)
			}
			operations := map[a.ID]nativeRetirementOperation{}
			if name != "missing" {
				operations[id] = operation
			}
			before["operations"], after["operations"] = marshal(operations), marshal(operations)
			badPrior, badCandidate := marshal(before), marshal(after)
			bad := proof
			bad.Prior, bad.Next = nativeRetirementDigest(badPrior), nativeRetirementDigest(badCandidate)
			if nativeServiceRetirementProof(marshal(bad), badPrior, badCandidate, binding, id) == nil {
				t.Fatal("accepted unbound retirement operation despite matching image hashes")
			}
		})
	}
	for _, field := range []string{"unrelated", "attachments", "revision"} {
		t.Run("candidate-"+field, func(t *testing.T) {
			var changed map[string]json.RawMessage
			if err := json.Unmarshal(candidate, &changed); err != nil {
				t.Fatal(err)
			}
			changed[field] = json.RawMessage(`null`)
			badCandidate := marshal(changed)
			bad := proof
			bad.Next = nativeRetirementDigest(badCandidate) // matching hash alone is insufficient
			if nativeServiceRetirementProof(marshal(bad), prior, badCandidate, binding, id) == nil {
				t.Fatal("accepted non-receipt-only candidate")
			}
		})
	}
}
