// Package consumercompat contains closed, public observation data, never authority.
package consumercompat

import (
	pc "dev.cengine/guest/internal/preparecompat"
	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
	"encoding/hex"
	"errors"
	"strings"
)

const Version uint32 = 3
const Profile = pc.FullProfile
const SameE = "same-e-existing-data"
const SameERootVersion uint32 = 6
const SameEFileVersion uint32 = 7
const SameEFileXattrVersion uint32 = 8
const SameEFileCapability = "security.capability"
const SameEFile = "same-e-retained-fd"
const SameEReconnectVersion uint32 = 5
const SameEReconnect = "same-e-old-leaf-reconnect"
const CrossE = "cross-e-old-leaf-reconnect"

var ErrInvalid = errors.New("consumercompat: invalid observation")

type BootBinding struct {
	ShimLaunchUUID string `json:"shimLaunchUUID"`
	GuestBootNonce string `json:"guestBootNonce"`
}
type WorkerScope struct {
	StoreUUID    string `json:"storeUUID"`
	ServiceEpoch string `json:"serviceEpoch"`
	WorkerUUID   string `json:"workerUUID"`
}

// No PREPARE field exists: only runtime consumers are implemented.
type RuntimeBinding struct {
	Store      string `json:"store"`
	Volume     string `json:"volume"`
	Attachment string `json:"attachment"`
	Container  string `json:"container"`
	Launch     string `json:"launch"`
	Key        string `json:"key"`
	Role       string `json:"role"`
	Mode       string `json:"mode"`
}
type Original struct {
	Epoch   string         `json:"epoch"`
	Binding RuntimeBinding `json:"binding"`
}

func OriginalFor(h a.DataHello) Original {
	b := h.Binding
	return Original{string(h.Epoch), RuntimeBinding{string(b.Store), string(b.Volume), string(b.Attachment), string(b.Container), string(b.Launch), string(b.Key), string(b.Role), string(b.Mode)}}
}

type Arm struct {
	Version             uint32      `json:"version"`
	Profile             string      `json:"profile"`
	RequestID           string      `json:"requestID"`
	ArmDigest           string      `json:"armDigest"`
	OperationUUID       string      `json:"operationUUID"`
	CaseName            string      `json:"caseName"`
	OriginalBootBinding BootBinding `json:"originalBootBinding"`
	Original            Original    `json:"original"`
	OriginalLeafSHA256  string      `json:"originalLeafSHA256"`
	WorkerScope         WorkerScope `json:"workerScope"`
}

// Query repeats the exact arm; no partial lookup can redirect an observation.
type Query = Arm
type Evidence struct {
	Hello              *a.DataHello `json:"hello,omitempty"`
	Stage              string       `json:"stage"`
	ErrorClass         string       `json:"errorClass"`
	StoreUUID          string       `json:"storeUUID"`
	ServiceEpoch       string       `json:"serviceEpoch"`
	RejectedLeafSHA256 string       `json:"rejectedLeafSHA256"`
	ByteCount          uint64       `json:"byteCount,omitempty"`
	PrefixSHA256       string       `json:"prefixSHA256,omitempty"`
	Admission          *Admission   `json:"admission,omitempty"`
}
type Admission struct {
	Original        Original `json:"original"`
	RequestSequence uint64   `json:"requestSequence"`
	// Version 6 binds the actual root GETATTR operands. Omitted in legacy v3.
	Operation      w.Operation `json:"operation,omitempty"`
	Node           w.NodeID    `json:"node,omitempty"`
	AuthKind       w.AuthKind  `json:"authKind,omitempty"`
	NoHandle       bool        `json:"noHandle,omitempty"`
	Handle         w.HandleID  `json:"handle,omitempty"`
	WriteOneAtZero bool        `json:"writeOneAtZero,omitempty"`
	CapabilityName string      `json:"capabilityName,omitempty"`
}
type Status struct {
	Query         Query     `json:"query"`
	State         string    `json:"state"`
	SelectedCount uint32    `json:"selectedCount"`
	Failure       string    `json:"failure,omitempty"`
	Evidence      *Evidence `json:"evidence,omitempty"`
}

func ID(s string) bool {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' || s[14] != '4' || !strings.ContainsRune("89ab", rune(s[19])) {
		return false
	}
	raw, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	return err == nil && len(raw) == 16 && strings.ToLower(s) == s
}
func Hash(s string) bool {
	raw, err := hex.DecodeString(s)
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == s
}
func ValidateArm(q Arm) error {
	b, w := q.Original.Binding, q.WorkerScope
	if (q.Version != Version && q.Version != 4 && q.Version != SameEReconnectVersion && q.Version != SameERootVersion && q.Version != SameEFileVersion && q.Version != SameEFileXattrVersion) || q.Profile != Profile || !ID(q.RequestID) || !Hash(q.ArmDigest) || !ID(q.OperationUUID) || !ID(q.OriginalBootBinding.ShimLaunchUUID) || !ID(q.OriginalBootBinding.GuestBootNonce) || q.OriginalBootBinding.ShimLaunchUUID != b.Launch || !ID(q.Original.Epoch) || !ID(b.Store) || !ID(b.Volume) || !ID(b.Attachment) || !ID(b.Launch) || !Hash(b.Container) || !Hash(b.Key) || b.Role != "runtime" || (b.Mode != "read-only" && b.Mode != "read-write") || !Hash(q.OriginalLeafSHA256) || !ID(w.StoreUUID) || !ID(w.ServiceEpoch) || !ID(w.WorkerUUID) || w.StoreUUID != b.Store {
		return ErrInvalid
	}
	if q.Version == SameEFileVersion || q.Version == SameEFileXattrVersion {
		if q.CaseName == SameEFile && q.Original.Epoch == w.ServiceEpoch && b.Mode == "read-write" {
			return nil
		}
		return ErrInvalid
	}
	if q.Version == SameERootVersion {
		if q.CaseName == SameE && q.Original.Epoch == w.ServiceEpoch {
			return nil
		}
		return ErrInvalid
	}
	if q.Version == SameEReconnectVersion {
		if q.CaseName == SameEReconnect && q.Original.Epoch == w.ServiceEpoch {
			return nil
		}
		return ErrInvalid
	}
	if q.Version == 4 {
		if WrongHelloCase(q.CaseName) && q.Original.Epoch == w.ServiceEpoch && (q.CaseName != WrongMode || b.Mode == "read-only") {
			return nil
		}
		return ErrInvalid
	}
	if q.CaseName == SameE && q.Original.Epoch == w.ServiceEpoch || q.CaseName == CrossE && q.Original.Epoch != w.ServiceEpoch {
		return nil
	}
	return ErrInvalid
}
func ValidateStatus(s Status) error {
	if ValidateArm(s.Query) != nil || s.SelectedCount > 1 {
		return ErrInvalid
	}
	switch s.State {
	case "armed":
		if s.SelectedCount == 0 && s.Failure == "" && s.Evidence == nil {
			return nil
		}
	case "claimed":
		if s.SelectedCount == 1 && s.Failure == "" && s.Evidence == nil {
			return nil
		}
	case "failed":
		switch s.Failure {
		case "duplicate", "mismatch", "timeout", "transport-or-unattributed", "not-existing", "not-blocked", "closed":
			if s.Evidence == nil {
				return nil
			}
		}
	case "observed", "finalized":
		e := s.Evidence
		if s.SelectedCount != 1 || s.Failure != "" || e == nil || e.StoreUUID != s.Query.WorkerScope.StoreUUID || e.ServiceEpoch != s.Query.WorkerScope.ServiceEpoch || e.RejectedLeafSHA256 != s.Query.OriginalLeafSHA256 {
			return ErrInvalid
		}
		if WrongHelloCase(s.Query.CaseName) && e.Stage == "pki-verify-peer" && e.ErrorClass == "unauthorized" && e.ByteCount > 0 && e.ByteCount <= 128<<10 && Hash(e.PrefixSHA256) && e.Admission == nil && e.Hello != nil && WrongHelloMatches(s.Query.CaseName, s.Query.Original, *e.Hello) {
			return nil
		}
		if s.Query.CaseName == SameEReconnect && e.Stage == "authenticate-data" && e.ErrorClass == "blocked" && e.ByteCount == 0 && e.PrefixSHA256 == "" && e.Admission == nil && e.Hello != nil && ExactOriginalHello(s.Query.Original, *e.Hello) {
			return nil
		}
		if e.Hello != nil {
			return ErrInvalid
		}
		if s.Query.CaseName == CrossE && e.Stage == "tls-client-certificate" && e.ErrorClass == "unknown-authority" && e.ByteCount > 0 && e.ByteCount <= 128<<10 && Hash(e.PrefixSHA256) && e.Admission == nil {
			return nil
		}
		if (s.Query.CaseName == SameE || s.Query.CaseName == SameEFile) && e.Stage == "request-admit" && e.ErrorClass == "blocked" && e.ByteCount == 0 && e.PrefixSHA256 == "" && e.Admission != nil && e.Admission.Original == s.Query.Original && e.Admission.RequestSequence > 0 {
			proof := e.Admission
			if s.Query.Version == SameEFileXattrVersion {
				if proof.Operation == w.OpGetXAttr && proof.Node != 0 && proof.AuthKind == w.CallerAuth && proof.NoHandle && proof.CapabilityName == SameEFileCapability && proof.Handle == 0 && !proof.WriteOneAtZero {
					return nil
				}
				return ErrInvalid
			}
			if proof.CapabilityName != "" {
				return ErrInvalid
			}
			if s.Query.Version == SameEFileVersion {
				if proof.Operation == w.OpWrite && proof.Node != 0 && proof.Handle != 0 && proof.WriteOneAtZero && !proof.NoHandle && (proof.AuthKind == w.CallerAuth || proof.AuthKind == w.OpenGrantAuth) {
					return nil
				}
				return ErrInvalid
			}
			if proof.Handle != 0 || proof.WriteOneAtZero {
				return ErrInvalid
			}
			if s.Query.Version == SameERootVersion {
				if proof.Operation == w.OpGetAttr && proof.Node != 0 && proof.AuthKind == w.NodeMetadataAuth && proof.NoHandle {
					return nil
				}
			} else if proof.Operation == "" && proof.Node == 0 && proof.AuthKind == 0 && !proof.NoHandle {
				return nil
			}
		}
	}
	return ErrInvalid
}
