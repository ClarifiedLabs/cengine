package storageboot

// The sole managed storage boot wire; obsolete boot envelopes are rejected.
import (
	"bytes"
	"crypto/ed25519"
	cc "dev.cengine/guest/internal/consumercompat"
	"dev.cengine/guest/internal/diskbootstrap"
	pc "dev.cengine/guest/internal/preparecompat"
	a "dev.cengine/guest/internal/storageauthority"
	p "dev.cengine/guest/internal/storagepki"
	s "dev.cengine/guest/internal/storageservice"
	"encoding/binary"
	"encoding/json"
	"io"
)

// LifecyclePort is the lifecycle TLS endpoint. Boot/CONTROL/CSR retain
// 4106/4107/4108 in an exclusively lifecycle-owned VM; DATA remains TCP 2049.
const LifecyclePort = 4117

const LifecycleBootVersion = "storage-service-lifecycle.v2"
const lifecycleMaxFrame = 65536

// lifecycleMaxNotifications bounds a notifications reply.
const lifecycleMaxNotifications = 32

type LifecycleConfiguration struct {
	Action          string                          `json:"action"`
	RootPublicKey   []byte                          `json:"root_public_key"`
	Signed          a.SignedLifecycleGrant          `json:"signed"`
	NowUnixSeconds  uint64                          `json:"now_unix_seconds"`
	LifetimeSeconds uint64                          `json:"lifetime_seconds"`
	Reopen          *p.SignedLifecycleServiceChange `json:"reopen,omitempty"`
	Cold            *a.SignedLifecycleColdOpen      `json:"cold,omitempty"`
	// Resume is the signed fresh-init resume authorization, present only for
	// action "resume-open-takeover". Same closed optional shape as Cold.
	Resume *a.SignedLifecycleResumeOpen `json:"resume,omitempty"`
}
type LifecycleReady struct {
	Identity        a.LifecycleIdentity `json:"identity"`
	ServiceEpoch    string              `json:"service_epoch"`
	WorkerUUID      string              `json:"worker_uuid"`
	ControllerEpoch uint64              `json:"controller_epoch"`
	ControllerKey   string              `json:"controller_key"`
	Revision        uint64              `json:"revision"`
	OpenRevision    uint64              `json:"open_revision"`
	BootstrapKey    string              `json:"bootstrap_key"`
	TLSRootDER      []byte              `json:"tls_root_der"`
	ServerDER       []byte              `json:"server_der"`
	ServerSPKI      string              `json:"server_spki"`
}
type LifecycleFrame struct {
	IsolationRequest                   *s.IsolationRequest          `json:"isolationRequest,omitempty"`
	IsolationProof                     *s.IsolationProof            `json:"isolationProof,omitempty"`
	ConsumerObservationArm             *cc.Arm                      `json:"consumerObservationArm,omitempty"`
	ConsumerObservationQuery           *cc.Query                    `json:"consumerObservationQuery,omitempty"`
	ConsumerObservationStatus          *cc.Status                   `json:"consumerObservationStatus,omitempty"`
	PrepareCompatibilityArm            *pc.StorageArm               `json:"prepareCompatibilityArm,omitempty"`
	PrepareCompatibilityQuery          *pc.StorageQuery             `json:"prepareCompatibilityQuery,omitempty"`
	PrepareCompatibilityRelease        *pc.StorageRelease           `json:"prepareCompatibilityRelease,omitempty"`
	PrepareCompatibilityWorkerExit     *pc.StorageRelease           `json:"prepareCompatibilityWorkerExit,omitempty"`
	PrepareCompatibilityWorkerWait     *pc.StorageWorkerWait        `json:"prepareCompatibilityWorkerWait,omitempty"`
	PrepareCompatibilityCheckpointExit *pc.WorkerCheckpointExit     `json:"prepareCompatibilityCheckpointExit,omitempty"`
	PrepareCompatibilityCheckpointAck  *pc.WorkerCheckpointExit     `json:"prepareCompatibilityCheckpointAck,omitempty"`
	PrepareCompatibilityCheckpointWait *pc.WorkerCheckpointWait     `json:"prepareCompatibilityCheckpointWait,omitempty"`
	PrepareCompatibilityStatus         *pc.StorageStatus            `json:"prepareCompatibilityStatus,omitempty"`
	Version                            string                       `json:"version"`
	Operation                          string                       `json:"operation"`
	Binding                            diskbootstrap.StorageBinding `json:"binding"`
	Configuration                      *LifecycleConfiguration      `json:"configuration,omitempty"`
	Ready                              *LifecycleReady              `json:"ready,omitempty"`
	Sequence                           *uint64                      `json:"sequence,omitempty"`
	ServiceEpoch                       string                       `json:"service_epoch,omitempty"`
	Command                            string                       `json:"command,omitempty"`
	CSR                                []byte                       `json:"csr,omitempty"`
	Signed                             *a.SignedLifecycleGrant      `json:"signed,omitempty"`
	Controller                         *a.Controller                `json:"controller,omitempty"`
	Certificate                        []byte                       `json:"certificate,omitempty"`
	OK                                 *bool                        `json:"ok,omitempty"`
	Code                               string                       `json:"code,omitempty"`
	// Same-worker replacement fields; frozen wire, supervisor behavior pending.
	WorkerUUID         string                       `json:"worker_uuid,omitempty"`
	ReplacementRequest *LifecycleReplacementRequest `json:"replacement_request,omitempty"`
	Status             *LifecycleServiceStatus      `json:"status,omitempty"`
	Replacement        *LifecycleReplacementStatus  `json:"replacement,omitempty"`
	// Notifications is the sole result of a notifications reply: a closed,
	// bounded list of storageauthority.DataHello {epoch, binding} entries.
	Notifications *[]a.DataHello            `json:"notifications,omitempty"`
	Handoff       *a.SignedLifecycleHandoff `json:"handoff,omitempty"`
	Nonce         []byte                    `json:"nonce,omitempty"`
	HandoffResult *LifecycleHandoffReply    `json:"handoff_result,omitempty"`
}

// replacement-status carries no request body: it is keyed only by the envelope
// predecessor pair (worker_uuid + service_epoch) of the replace-service command.

// LifecycleReplacementRequest names the lost worker and the open-only successor configuration.
type LifecycleReplacementRequest struct {
	PredecessorWorkerUUID string                 `json:"predecessor_worker_uuid"`
	Configuration         LifecycleConfiguration `json:"configuration"`
}

// LifecycleServiceStatus is envelope-bound; no scope is carried here.
type LifecycleServiceStatus struct {
	Phase string `json:"phase"`
}
type LifecycleReplacementStatus struct {
	Request LifecycleReplacementRequest `json:"request"`
	Phase   string                      `json:"phase"`
	Ready   *LifecycleReady             `json:"ready,omitempty"`
	Code    string                      `json:"code,omitempty"`
}

func (r *LifecycleReplacementRequest) validate() error {
	if r == nil || !id(r.PredecessorWorkerUUID) || r.Configuration.Action != "open" {
		return errFrame
	}
	return r.Configuration.validate()
}
func (s *LifecycleServiceStatus) validate() error {
	if s != nil {
		switch s.Phase {
		case "ready", "worker-lost", "replacing", "failed":
			return nil
		}
	}
	return errFrame
}
func (s *LifecycleReplacementStatus) validate() error {
	if s == nil || s.Request.validate() != nil {
		return errFrame
	}
	switch s.Phase {
	case "pending":
		if s.Ready == nil && s.Code == "" {
			return nil
		}
	case "succeeded":
		if s.Code == "" && lifecycleReadyValid(s.Ready) {
			return nil
		}
	case "failed":
		if s.Ready == nil && (s.Code == "replacement-failed" || s.Code == "worker-unreaped") {
			return nil
		}
	}
	return errFrame
}

func lifecycleFrame(op string, b diskbootstrap.StorageBinding) LifecycleFrame {
	return LifecycleFrame{Version: LifecycleBootVersion, Operation: op, Binding: b}
}
func lifecycleDER(b []byte) bool { return len(b) > 0 && len(b) <= 16384 }
func lifecycleSigned(s a.SignedLifecycleGrant) bool {
	return s.Grant.Validate() == nil && len(s.Signature) == 64
}
func lifecycleReadyValid(r *LifecycleReady) bool {
	return r != nil && r.Identity.Validate() == nil && id(r.ServiceEpoch) && id(r.WorkerUUID) && r.ControllerEpoch > 0 && r.Revision > 0 && r.OpenRevision > 0 && r.OpenRevision <= r.Revision && pin(r.ControllerKey) && pin(r.BootstrapKey) && pin(r.ServerSPKI) && lifecycleDER(r.TLSRootDER) && lifecycleDER(r.ServerDER)
}

func (c *LifecycleConfiguration) validate() error {
	if c == nil || len(c.RootPublicKey) != ed25519.PublicKeySize || !lifecycleSigned(c.Signed) || c.NowUnixSeconds == 0 || c.NowUnixSeconds > 253402214399 || c.LifetimeSeconds == 0 || c.LifetimeSeconds > 86400 || c.Signed.Grant.Operation == a.LifecycleRetire {
		return errFrame
	}
	switch c.Action {
	case "initialize":
		if c.Reopen != nil || c.Cold != nil || c.Resume != nil || c.Signed.Grant.Operation != a.LifecycleInitialize {
			return errFrame
		}
	case "open":
		// ROOT authorization (signature + recorded bootstrap key) is verified
		// here so no caller can kill, start, or open without it.
		if c.Cold != nil || c.Resume != nil || c.Reopen == nil || c.Reopen.Verify(ed25519.PublicKey(c.RootPublicKey)) != nil || c.Signed.Grant != c.Reopen.Request.Predecessor.Grant {
			return errFrame
		}
	case "cold-open-takeover":
		if c.Reopen != nil || c.Resume != nil || c.Cold == nil || c.Cold.Validate() != nil ||
			!lifecycleSignedEqual(c.Signed, c.Cold.Request.Takeover) ||
			c.NowUnixSeconds != c.Cold.Request.NowUnixSeconds || c.LifetimeSeconds != c.Cold.Request.LifetimeSeconds ||
			a.VerifyLifecycleColdOpen(ed25519.PublicKey(c.RootPublicKey), *c.Cold) != nil {
			return errFrame
		}
	case "resume-open-takeover":
		// Fresh-init resume: no predecessor service epoch exists, so the
		// unsigned original initialize grant rides inside ROOT's outer
		// signature. Same closed shape as cold: exactly one signed resume,
		// the boot grant must be its exact takeover, and clock fields match.
		if c.Reopen != nil || c.Cold != nil || c.Resume == nil || c.Resume.Validate() != nil ||
			!lifecycleSignedEqual(c.Signed, c.Resume.Request.Takeover) ||
			c.NowUnixSeconds != c.Resume.Request.NowUnixSeconds || c.LifetimeSeconds != c.Resume.Request.LifetimeSeconds ||
			a.VerifyLifecycleResumeOpen(ed25519.PublicKey(c.RootPublicKey), *c.Resume) != nil {
			return errFrame
		}
	default:
		return errFrame
	}
	return nil
}

// json.Number is essential: float64 would silently round full-width serials/epochs.
func lifecycleCanonical(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var tree any
	if err = dec.Decode(&tree); err != nil {
		return nil, err
	}
	return json.Marshal(tree)
}
func (f *LifecycleFrame) validate() error {
	if f == nil || f.Version != LifecycleBootVersion || !validBinding(f.Binding) {
		return errFrame
	}
	if f.Sequence != nil && *f.Sequence == 0 || f.ServiceEpoch != "" && !id(f.ServiceEpoch) || f.WorkerUUID != "" && !id(f.WorkerUUID) {
		return errFrame
	}
	if f.ReplacementRequest != nil && f.ReplacementRequest.validate() != nil || f.Status != nil && f.Status.validate() != nil || f.Replacement != nil && f.Replacement.validate() != nil {
		return errFrame
	}
	if f.CSR != nil && !lifecycleDER(f.CSR) || f.Certificate != nil && !lifecycleDER(f.Certificate) {
		return errFrame
	}
	if f.Signed != nil && !lifecycleSigned(*f.Signed) {
		return errFrame
	}
	if f.Controller != nil && (f.Controller.Epoch == 0 || !pin(string(f.Controller.Key))) {
		return errFrame
	}
	if f.OK != nil && !*f.OK {
		return errFrame
	}
	if f.Code != "" {
		switch f.Code {
		case "configuration", "binding-mismatch", "sequence", "command", "service", "invalid-frame",
			"stale-worker", "worker-busy", "worker-lost", "worker-unreaped", "replacement-conflict":
		default:
			return errFrame
		}
	}
	if f.Notifications != nil {
		if len(*f.Notifications) > lifecycleMaxNotifications {
			return errFrame
		}
		for _, n := range *f.Notifications {
			if !validNotification(n) {
				return errFrame
			}
		}
	}
	allowed := map[string]bool{"version": true, "operation": true, "binding": true}
	add := func(keys ...string) {
		for _, k := range keys {
			allowed[k] = true
		}
	}
	switch f.Operation {
	case "hello":
	case "configure":
		add("configuration")
		if f.Configuration.validate() != nil {
			return errFrame
		}
	case "ready":
		add("ready")
		if !lifecycleReadyValid(f.Ready) {
			return errFrame
		}
	case "error":
		add("code")
		if f.Code == "" {
			return errFrame
		}
	case "command":
		add("sequence", "service_epoch", "worker_uuid", "command")
		switch f.Command {
		case "isolation-state", "legacy-connection", "second-service-exclusivity":
			add("isolationRequest")
			if !validIsolationRequest(f.IsolationRequest) {
				return errFrame
			}
		case "consumer-observation-arm":
			add("consumerObservationArm")
			if !validLifecycleConsumerRequest(f) {
				return errFrame
			}
		case "consumer-observation-query", "consumer-observation-finalize":
			add("consumerObservationQuery")
			if !validLifecycleConsumerRequest(f) {
				return errFrame
			}
		case "prepare-compatibility-arm":
			add("prepareCompatibilityArm")
			if f.PrepareCompatibilityArm == nil || pc.ValidateStorageArm(*f.PrepareCompatibilityArm) != nil || f.PrepareCompatibilityArm.WorkerUUID != f.WorkerUUID || f.PrepareCompatibilityArm.Arm.Scope.ServiceEpoch != f.ServiceEpoch {
				return errFrame
			}
		case "prepare-compatibility-observe":
			add("prepareCompatibilityQuery")
			if f.PrepareCompatibilityQuery == nil || pc.ValidateStorageQuery(*f.PrepareCompatibilityQuery) != nil || f.PrepareCompatibilityQuery.WorkerUUID != f.WorkerUUID {
				return errFrame
			}
		case "prepare-compatibility-release":
			add("prepareCompatibilityRelease")
			if f.PrepareCompatibilityRelease == nil || pc.ValidateStorageRelease(*f.PrepareCompatibilityRelease) != nil || f.PrepareCompatibilityRelease.Query.WorkerUUID != f.WorkerUUID {
				return errFrame
			}
		case "prepare-compatibility-worker-exit":
			add("prepareCompatibilityWorkerExit")
			r := f.PrepareCompatibilityWorkerExit
			if r == nil || pc.ValidateStorageRelease(*r) != nil || (r.Stage != "full-frame-before-admit" && r.Stage != "admitted-queued") || r.Query.WorkerUUID != f.WorkerUUID {
				return errFrame
			}
		case "prepare-compatibility-checkpoint-exit":
			add("prepareCompatibilityCheckpointExit")
			r := f.PrepareCompatibilityCheckpointExit
			if r == nil || pc.ValidateWorkerCheckpointExit(*r) != nil || r.WorkerUUID != f.WorkerUUID || r.Arm.Scope.ServiceEpoch != f.ServiceEpoch {
				return errFrame
			}
		case "issue-controller":
			add("csr")
			if !lifecycleDER(f.CSR) {
				return errFrame
			}
		case "authorize-successor":
			add("csr", "signed")
			if !lifecycleDER(f.CSR) || f.Signed == nil || f.Signed.Grant.Operation != a.LifecycleTakeover {
				return errFrame
			}
		case "authorize-retirement":
			add("signed")
			if f.Signed == nil || f.Signed.Grant.Operation != a.LifecycleRetire {
				return errFrame
			}
		case "fence-handoff":
			add("handoff", "nonce")
			if f.Handoff == nil || f.Handoff.Request.Validate() != nil || len(f.Handoff.Signature) != ed25519.SignatureSize || len(f.Nonce) != 32 || string(f.Handoff.Request.ServiceEpoch) != f.ServiceEpoch {
				return errFrame
			}
		case "reconcile-controller":
			add("controller", "signed")
			if f.Controller == nil || f.Signed == nil {
				return errFrame
			}
		case "replace-service":
			add("replacement_request")
			r := f.ReplacementRequest
			if r == nil || r.Configuration.Reopen == nil || f.WorkerUUID != r.PredecessorWorkerUUID || f.ServiceEpoch != r.Configuration.Reopen.Request.Predecessor.Context.ServiceEpoch {
				return errFrame
			}
		case "query", "service-status", "replacement-status", "notifications":
		default:
			return errFrame
		}
	case "reply":
		add("sequence", "service_epoch", "worker_uuid")
		n := 0
		if f.HandoffResult != nil {
			if !validLifecycleHandoffReply(f.HandoffResult) || string(f.HandoffResult.Result.Request.ServiceEpoch) != f.ServiceEpoch || f.HandoffResult.Ready.WorkerUUID != f.WorkerUUID {
				return errFrame
			}
			add("handoff_result")
			n++
		}
		if f.IsolationProof != nil {
			if !validLifecycleIsolationProof(f) {
				return errFrame
			}
			add("isolationProof")
			n++
		}
		if status := f.ConsumerObservationStatus; status != nil {
			if cc.ValidateStatus(*status) != nil || !lifecycleConsumerScope(f, &status.Query) {
				return errFrame
			}
			add("consumerObservationStatus")
			n++
		}
		for key, present := range map[string]bool{
			"prepareCompatibilityStatus":         f.PrepareCompatibilityStatus != nil,
			"prepareCompatibilityWorkerWait":     f.PrepareCompatibilityWorkerWait != nil,
			"prepareCompatibilityCheckpointAck":  f.PrepareCompatibilityCheckpointAck != nil,
			"prepareCompatibilityCheckpointWait": f.PrepareCompatibilityCheckpointWait != nil,
		} {
			if present {
				add(key)
				n++
			}
		}
		if f.Status != nil {
			add("status")
			n++
		}
		if f.Replacement != nil {
			add("replacement")
			n++
		}
		if f.Notifications != nil {
			add("notifications")
			n++
		}
		if f.Ready != nil {
			if !lifecycleReadyValid(f.Ready) {
				return errFrame
			}
			add("ready")
			n++
		}
		if f.Certificate != nil {
			add("certificate")
			n++
		}
		if f.OK != nil {
			add("ok")
			n++
		}
		if f.Code != "" {
			add("code")
			n++
		}
		if n != 1 {
			return errFrame
		}
	default:
		return errFrame
	}
	if (f.Operation == "command" || f.Operation == "reply") && (f.Sequence == nil || f.ServiceEpoch == "" || f.WorkerUUID == "") {
		return errFrame
	}
	raw, _ := json.Marshal(f)
	if !validCompatibilityRaw(raw) {
		return errFrame
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	if len(fields) != len(allowed) {
		return errFrame
	}
	for k := range fields {
		if !allowed[k] {
			return errFrame
		}
	}
	return nil
}
func DecodeLifecycleFrame(body []byte) (*LifecycleFrame, error) {
	if len(body) == 0 || len(body) > lifecycleMaxFrame {
		return nil, errFrame
	}
	var f LifecycleFrame
	if !validCompatibilityRaw(body) || json.Unmarshal(body, &f) != nil || f.validate() != nil {
		return nil, errFrame
	}
	canonical, err := lifecycleCanonical(&f)
	if err != nil || !bytes.Equal(body, canonical) {
		return nil, errFrame
	}
	return &f, nil
}
func EncodeLifecycleFrame(f *LifecycleFrame) ([]byte, error) {
	if f.validate() != nil {
		return nil, errFrame
	}
	body, err := lifecycleCanonical(f)
	if err != nil || len(body) > lifecycleMaxFrame {
		return nil, errFrame
	}
	out := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(out, uint32(len(body)))
	copy(out[4:], body)
	return out, nil
}
func WriteLifecycleFrame(w io.Writer, f *LifecycleFrame) error {
	b, err := EncodeLifecycleFrame(f)
	if err != nil {
		return err
	}
	for len(b) > 0 {
		n, e := w.Write(b)
		if n < 0 || n > len(b) {
			return io.ErrShortWrite
		}
		b = b[n:]
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
func ReadLifecycleFrame(r io.Reader) (*LifecycleFrame, error) {
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(h[:])
	if n == 0 || n > lifecycleMaxFrame {
		return nil, errFrame
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return DecodeLifecycleFrame(b)
}
