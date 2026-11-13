package storageauthority

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"io"
)

// Declaration order is ROOT's frozen observation signing contract.
type LifecycleColdObservationRequest struct {
	ObservationID ID                  `json:"observation_id"`
	Subject       []byte              `json:"subject"`
	Observer      LifecycleColdLaunch `json:"observer"`
}
type SignedLifecycleColdObservation struct {
	Request   LifecycleColdObservationRequest `json:"request"`
	Signature []byte                          `json:"signature"`
}
type LifecycleColdObservation struct {
	RequestSHA256 string                   `json:"request_sha256"`
	Outcome       string                   `json:"outcome"`
	Predecessor   LifecycleColdPredecessor `json:"predecessor"`
}

func (r LifecycleColdObservationRequest) SubjectOpen() (SignedLifecycleColdOpen, error) {
	var s SignedLifecycleColdOpen
	if len(r.Subject) == 0 || len(r.Subject) > 65536 {
		return s, ErrInvalid
	}
	// Reject recursion before typed decoding, including explicit null observation.
	var envelope struct {
		Request map[string]json.RawMessage `json:"request"`
	}
	if json.Unmarshal(r.Subject, &envelope) != nil {
		return s, ErrInvalid
	}
	if _, present := envelope.Request["observation"]; present {
		return s, ErrInvalid
	}
	dec := json.NewDecoder(bytes.NewReader(r.Subject))
	dec.DisallowUnknownFields()
	if dec.Decode(&s) != nil || dec.Decode(new(any)) != io.EOF || s.Validate() != nil {
		return s, ErrInvalid
	}
	// Subject uses the existing canonical (sorted-key) SignedOpen JSON wire.
	var tree any
	dec = json.NewDecoder(bytes.NewReader(r.Subject))
	dec.UseNumber()
	if dec.Decode(&tree) != nil {
		return s, ErrInvalid
	}
	canonical, err := json.Marshal(tree)
	if err != nil || !bytes.Equal(canonical, r.Subject) {
		return s, ErrInvalid
	}
	return s, nil
}
func (r LifecycleColdObservationRequest) Validate() error {
	s, err := r.SubjectOpen()
	if err != nil {
		return err
	}
	old, l := s.Request.Launch, r.Observer
	if !validID(r.ObservationID) || r.ObservationID == s.Request.OperationID || !validID(l.ShimLaunchUUID) || l.ShimLaunchUUID == old.ShimLaunchUUID || !validKey(Fingerprint(l.SpecSHA256)) || !validKey(Fingerprint(l.InitramfsSHA256)) || l.Ext4UUID != old.Ext4UUID || l.Bytes != old.Bytes {
		return ErrInvalid
	}
	return nil
}
func (s SignedLifecycleColdObservation) Clone() SignedLifecycleColdObservation {
	s.Signature = bytes.Clone(s.Signature)
	s.Request.Subject = bytes.Clone(s.Request.Subject)
	return s
}
func (s SignedLifecycleColdObservation) Validate() error {
	if len(s.Signature) != ed25519.SignatureSize {
		return ErrInvalid
	}
	return s.Request.Validate()
}
func LifecycleColdObservationSigningBytes(r LifecycleColdObservationRequest) ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(r)
	return append([]byte("cengine.storageauthority.lifecycle-cold-observe.v1\x00"), b...), err
}
func (r LifecycleColdObservationRequest) Digest() string {
	b, _ := LifecycleColdObservationSigningBytes(r)
	return contentDigest(b)
}
func VerifyLifecycleColdObservation(root ed25519.PublicKey, s SignedLifecycleColdObservation) error {
	if err := s.Validate(); err != nil {
		return err
	}
	old, err := s.Request.SubjectOpen()
	if err != nil {
		return err
	}
	if err = VerifyLifecycleColdOpen(root, old); err != nil {
		return err
	}
	b, err := LifecycleColdObservationSigningBytes(s.Request)
	if err != nil {
		return err
	}
	if !ed25519.Verify(root, b, s.Signature) {
		return ErrUnauthorized
	}
	return nil
}
func observationProjection(p LifecycleColdPredecessor, old LifecycleColdOpenRequest) bool {
	prior := old.Predecessor
	return p == prior || (p.CurrentGrant == old.Takeover.Grant && p.ControllerEpoch == prior.ControllerEpoch+1 && p.ControllerKey == old.Takeover.Grant.NewKey && validID(p.ServiceEpoch) && p.ServiceEpoch != prior.ServiceEpoch && p.OpenRevision > prior.OpenRevision && p.BootstrapKey == prior.BootstrapKey)
}
func (o LifecycleColdObservation) ValidateFor(r LifecycleColdObservationRequest) error {
	if r.Validate() != nil || o.RequestSHA256 != r.Digest() {
		return ErrInvalid
	}
	s, _ := r.SubjectOpen()
	if o.Outcome == "unchanged" && o.Predecessor == s.Request.Predecessor {
		return nil
	}
	if o.Outcome == "applied" && o.Predecessor != s.Request.Predecessor && observationProjection(o.Predecessor, s.Request) {
		return nil
	}
	return ErrInvalid
}

// ObserveLifecycleColdReadOnly returns only a projection, never an authority.
// It does not recover, clean, save, sync, or call a durability barrier.
func ObserveLifecycleColdReadOnly(c Config, signed SignedLifecycleColdObservation) (LifecycleColdObservation, error) {
	signed = signed.Clone()
	c, err := configured(c)
	if err != nil {
		return LifecycleColdObservation{}, err
	}
	if err = VerifyLifecycleColdObservation(c.BootstrapKey, signed); err != nil {
		return LifecycleColdObservation{}, err
	}
	j, err := probeJournal(c)
	if err != nil {
		return LifecycleColdObservation{}, err
	}
	defer j.close()
	if _, err = j.readLifecycleArtifact(stateName, j.maxBytes); err != nil {
		return LifecycleColdObservation{}, err
	}
	state, err := j.load()
	if err != nil {
		return LifecycleColdObservation{}, err
	}
	root, err := identity(j.root)
	if err != nil {
		return LifecycleColdObservation{}, err
	}
	exports, err := identity(j.exports)
	if err != nil {
		return LifecycleColdObservation{}, err
	}
	pin, _ := PublicKeyFingerprint(c.BootstrapKey)
	old, _ := signed.Request.SubjectOpen()
	if state.Store.ID != old.Request.Predecessor.CurrentGrant.Identity.Store || state.Store.DeviceID != c.DeviceID || state.Store.Root != root || state.Store.Exports != exports || state.Bootstrap != pin {
		return LifecycleColdObservation{}, ErrConflict
	}
	a := &Authority{s: state, j: j, limits: c.Limits}
	return a.observeColdLocked(signed.Request)
}

// The caller holds the actual journal flock. Also used by takeover admission,
// before expected-startup checks and every cleanup/recovery/publication write.
func (a *Authority) observeColdLocked(r LifecycleColdObservationRequest) (LifecycleColdObservation, error) {
	fail := func(err error) (LifecycleColdObservation, error) { return LifecycleColdObservation{}, err }
	if r.Validate() != nil {
		return fail(ErrInvalid)
	}
	if a.s.Schema != LifecycleSchemaVersion || a.s.Lifecycle == nil {
		return fail(ErrInvalid)
	}
	if a.s.Lifecycle.Retiring != nil {
		return fail(ErrBlocked)
	}
	if err := a.validate(); err != nil {
		return fail(err)
	}
	if err := a.j.lifecycleNamespaceClean(); err != nil {
		return fail(err)
	}
	for id, v := range a.s.Volumes {
		phase := a.s.VolumeLifecycles[id].Phase
		if phase == VolumeCreating || phase == VolumeDeleting {
			return fail(ErrRepairRequired)
		}
		if phase == VolumeDeleted {
			if err := a.deletedRootAbsent(v); err != nil {
				return fail(err)
			}
			continue
		}
		root, err := a.j.volume(v)
		if err != nil {
			return fail(err)
		}
		root.Close()
	}
	old, _ := r.SubjectOpen()
	p := old.Request.Predecessor
	l := a.s.Lifecycle
	if l.Identity != p.CurrentGrant.Identity || a.s.Bootstrap != p.BootstrapKey {
		return fail(ErrConflict)
	}
	actual := LifecycleColdPredecessor{l.Latest.Grant, a.s.Epoch, a.s.Controller.Epoch, a.s.Controller.Key, l.OpenRevision, a.s.Bootstrap}
	o := LifecycleColdObservation{r.Digest(), "unchanged", actual}
	if actual == p {
		return o, nil
	}
	m := l.ColdApplied
	if m == nil || m.RequestSHA256 != coldRequestDigest(old.Request) || m.GrantID != old.Request.Takeover.Grant.ID || m.ServiceEpoch != a.s.Epoch || m.OpenRevision != l.OpenRevision || m.OpenRevision != a.s.Revision || l.Latest.Revision != m.OpenRevision {
		return fail(ErrConflict)
	}
	o.Outcome = "applied"
	if err := o.ValidateFor(r); err != nil {
		return fail(err)
	}
	return o, nil
}
