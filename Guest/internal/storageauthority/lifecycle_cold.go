package storageauthority

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
)

// ErrLifecycleColdAlreadyApplied is a read-only constructor result, not a live
// authority. Reconcile the surviving service before attempting another open.
var ErrLifecycleColdAlreadyApplied = errors.New("lifecycle cold open already applied")

// Declaration order is the frozen ROOT signing contract.
type LifecycleColdPredecessor struct {
	CurrentGrant    LifecycleGrant `json:"current_grant"`
	ServiceEpoch    ID             `json:"service_epoch"`
	ControllerEpoch uint64         `json:"controller_epoch"`
	ControllerKey   Fingerprint    `json:"controller_key"`
	OpenRevision    uint64         `json:"open_revision"`
	BootstrapKey    Fingerprint    `json:"bootstrap_key"`
}

type LifecycleColdLaunch struct {
	ShimLaunchUUID  ID     `json:"shim_launch_uuid"`
	SpecSHA256      string `json:"spec_sha256"`
	InitramfsSHA256 string `json:"initramfs_sha256"`
	Ext4UUID        string `json:"ext4_uuid"`
	Bytes           uint64 `json:"bytes"`
}

type LifecycleColdOpenRequest struct {
	OperationID     ID                       `json:"operation_id"`
	Predecessor     LifecycleColdPredecessor `json:"predecessor"`
	Takeover        SignedLifecycleGrant     `json:"takeover"`
	Launch          LifecycleColdLaunch      `json:"launch"`
	NowUnixSeconds  uint64                   `json:"now_unix_seconds"`
	LifetimeSeconds uint64                   `json:"lifetime_seconds"`
}

type SignedLifecycleColdOpen struct {
	Request   LifecycleColdOpenRequest `json:"request"`
	Signature []byte                   `json:"signature"`
}

func (r LifecycleColdOpenRequest) Validate() error {
	p, g, l := r.Predecessor, r.Takeover.Grant, r.Launch
	if !validID(r.OperationID) || r.OperationID != g.ID || p.CurrentGrant.Validate() != nil ||
		(p.CurrentGrant.Operation != LifecycleInitialize && p.CurrentGrant.Operation != LifecycleTakeover) ||
		!validID(p.ServiceEpoch) || p.ControllerEpoch != p.CurrentGrant.ExpectedEpoch+1 ||
		p.ControllerKey != p.CurrentGrant.NewKey || p.OpenRevision == 0 || !validKey(p.BootstrapKey) || p.ControllerKey == p.BootstrapKey ||
		g.Validate() != nil || g.Operation != LifecycleTakeover || g.Identity != p.CurrentGrant.Identity ||
		g.ExpectedEpoch != p.ControllerEpoch || g.Serial <= p.CurrentGrant.Serial || g.ID == p.CurrentGrant.ID ||
		g.NewKey == p.ControllerKey || g.NewKey == p.BootstrapKey || len(r.Takeover.Signature) != ed25519.SignatureSize ||
		!validID(l.ShimLaunchUUID) || !validKey(Fingerprint(l.SpecSHA256)) || !validKey(Fingerprint(l.InitramfsSHA256)) ||
		!validColdExt4UUID(l.Ext4UUID) || l.Bytes == 0 || l.Bytes > 1<<63-1 ||
		r.NowUnixSeconds == 0 || r.NowUnixSeconds > 253402300799 || r.LifetimeSeconds == 0 || r.LifetimeSeconds > 86400 ||
		r.LifetimeSeconds > 253402300799-r.NowUnixSeconds {
		return ErrInvalid
	}
	return nil
}

func validColdExt4UUID(s string) bool {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' || s != strings.ToLower(s) || s == "00000000-0000-0000-0000-000000000000" {
		return false
	}
	b, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	return err == nil && len(b) == 16
}

func (s SignedLifecycleColdOpen) Validate() error {
	if s.Request.Validate() != nil || len(s.Signature) != ed25519.SignatureSize {
		return ErrInvalid
	}
	return nil
}

func LifecycleColdOpenSigningBytes(r LifecycleColdOpenRequest) ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	return append([]byte("cengine.storageauthority.lifecycle-cold-open.v1\x00"), b...), nil
}

// VerifyLifecycleColdOpen binds both signatures and the predecessor bootstrap
// fingerprint to one copied ROOT pin. Launch/time checks are structural; callers
// must separately compare these signed values with their observed launch.
func VerifyLifecycleColdOpen(root ed25519.PublicKey, signed SignedLifecycleColdOpen) error {
	root = append(ed25519.PublicKey(nil), root...)
	if err := signed.Validate(); err != nil {
		return err
	}
	if len(root) != ed25519.PublicKeySize {
		return ErrUnauthorized
	}
	pin, err := PublicKeyFingerprint(root)
	if err != nil || pin != signed.Request.Predecessor.BootstrapKey {
		return ErrUnauthorized
	}
	if err := verifyLifecycle(root, signed.Request.Takeover); err != nil {
		return err
	}
	msg, err := LifecycleColdOpenSigningBytes(signed.Request)
	if err != nil {
		return err
	}
	if !ed25519.Verify(root, msg, signed.Signature) {
		return ErrUnauthorized
	}
	return nil
}

// ColdOpenAndTakeover consumes the exact signed predecessor with one startup
// commit under one journal flock.
func ColdOpenAndTakeover(c Config, signed SignedLifecycleColdOpen) (*Authority, error) {
	var err error
	c, err = configured(c)
	if err != nil {
		return nil, err
	}
	// Own the signature slices before verification and request hashing.
	signed.Signature = append([]byte(nil), signed.Signature...)
	signed.Request.Takeover.Signature = append([]byte(nil), signed.Request.Takeover.Signature...)
	if err = VerifyLifecycleColdOpen(c.BootstrapKey, signed); err != nil {
		return nil, err
	}
	r := signed.Request
	p := r.Predecessor
	expected := ExpectedLifecycleStartup{ExpectedStartup{p.CurrentGrant.Identity.Store, p.ServiceEpoch, Controller{p.ControllerEpoch, p.ControllerKey}}, p.OpenRevision}
	return openAuthority(c, nil, &expected.ExpectedStartup, &lifecycleOpen{identity: p.CurrentGrant.Identity, current: &p.CurrentGrant, expected: &expected, cold: &r})
}

type lifecycleColdApplied struct {
	RequestSHA256 string `json:"request_sha256"`
	GrantID       ID     `json:"grant_id"`
	ServiceEpoch  ID     `json:"service_epoch"`
	OpenRevision  uint64 `json:"open_revision"`
}

func coldRequestDigest(r LifecycleColdOpenRequest) string {
	b, _ := LifecycleColdOpenSigningBytes(r)
	return contentDigest(b)
}

func (a *Authority) admitColdOpen(r LifecycleColdOpenRequest) error {
	if m := a.s.Lifecycle.ColdApplied; m != nil && m.RequestSHA256 == coldRequestDigest(r) && a.s.Lifecycle.Latest.Grant == r.Takeover.Grant {
		// An interrupted cold publication is NOT proven workload recovery.
		if err := a.j.lifecycleNamespaceClean(); err != nil {
			return err
		}
		return ErrLifecycleColdAlreadyApplied
	}
	if a.s.Bootstrap != r.Predecessor.BootstrapKey {
		return ErrConflict
	}
	if a.keyUsed(r.Takeover.Grant.NewKey) {
		return ErrUnauthorized
	}
	return nil
}
