package storageauthority

import "encoding/json"

// LifecycleVersion names the active signed lifecycle wire contract. These DTOs
// are not principals; transitions separately verify signatures and authority.
const LifecycleVersion = "storage-lifecycle.v2"

type LifecycleOperation string

const (
	LifecycleInitialize LifecycleOperation = "initialize"
	LifecycleTakeover   LifecycleOperation = "takeover"
	LifecycleRetire     LifecycleOperation = "retire"
)

// Declaration order is part of the signing contract; do not reorder fields.
type LifecycleIdentity struct {
	Store      ID          `json:"store"`
	Generation uint64      `json:"generation"`
	Binding    Fingerprint `json:"binding"`
}

type LifecycleGrant struct {
	Operation     LifecycleOperation `json:"operation"`
	ID            ID                 `json:"id"`
	Identity      LifecycleIdentity  `json:"identity"`
	Serial        uint64             `json:"serial"`
	ExpectedEpoch uint64             `json:"expected_epoch"`
	NewKey        Fingerprint        `json:"new_key"`
}

// LifecycleReceipt is a direct-child result DTO, NOT an authentication capability
// or proof of drain. Owners must separately authenticate and correlate its source.
type LifecycleReceipt struct {
	Grant        LifecycleGrant `json:"grant"`
	Nonce        []byte         `json:"nonce"`
	ServiceEpoch ID             `json:"service_epoch"`
	Revision     uint64         `json:"revision"`
}

// LifecycleServiceResult describes the live open, not the grant's stable applied
// receipt. It is a transport DTO, not a principal or a self-authenticating proof.
// Declaration order is the frozen signing contract; do not reorder fields.
type LifecycleServiceResult struct {
	Identity        LifecycleIdentity `json:"identity"`
	Grant           LifecycleGrant    `json:"grant"`
	Nonce           []byte            `json:"nonce"`
	ServiceEpoch    ID                `json:"service_epoch"`
	ControllerEpoch uint64            `json:"controller_epoch"`
	ControllerKey   Fingerprint       `json:"controller_key"`
	OpenRevision    uint64            `json:"open_revision"`
}

func (r LifecycleServiceResult) Validate() error {
	if r.Grant.Validate() != nil || r.Identity != r.Grant.Identity ||
		(r.Grant.Operation != LifecycleInitialize && r.Grant.Operation != LifecycleTakeover) ||
		len(r.Nonce) != 32 || !validID(r.ServiceEpoch) || r.ControllerEpoch != r.Grant.ExpectedEpoch+1 ||
		r.ControllerKey != r.Grant.NewKey || r.OpenRevision == 0 {
		return ErrInvalid
	}
	return nil
}

func LifecycleServiceResultSigningBytes(r LifecycleServiceResult) ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	return append([]byte("cengine.storageauthority.lifecycle-service-result.v2\x00"), b...), nil
}

func (i LifecycleIdentity) Validate() error {
	if !validID(i.Store) || i.Generation == 0 || !validKey(i.Binding) {
		return ErrInvalid
	}
	return nil
}

func (g LifecycleGrant) Validate() error {
	if g.Identity.Validate() != nil || !validID(g.ID) || g.Serial == 0 || !validKey(g.NewKey) {
		return ErrInvalid
	}
	switch g.Operation {
	case LifecycleInitialize:
		if g.ExpectedEpoch != 0 {
			return ErrInvalid
		}
	case LifecycleTakeover:
		if g.ExpectedEpoch == 0 || g.ExpectedEpoch == ^uint64(0) {
			return ErrInvalid
		}
	case LifecycleRetire:
		if g.ExpectedEpoch == 0 {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func (r LifecycleReceipt) Validate() error {
	if r.Grant.Validate() != nil || len(r.Nonce) != 32 || !validID(r.ServiceEpoch) || r.Revision == 0 {
		return ErrInvalid
	}
	return nil
}

// LifecycleGrantSigningBytes matches Swift StorageLifecycleProtocol.Grant.
// json.Marshal uses declaration order, distinct from the sorted-key transport.
func LifecycleGrantSigningBytes(g LifecycleGrant) ([]byte, error) {
	if err := g.Validate(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(g)
	if err != nil {
		return nil, err
	}
	return append([]byte("cengine.storageauthority.lifecycle.v2\x00"), b...), nil
}

func LifecycleReceiptSigningBytes(r LifecycleReceipt) ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	return append([]byte("cengine.storageauthority.lifecycle-receipt.v2\x00"), b...), nil
}
