package storagebootstrap

// Private protocol adapters are called only by the native inherited-parent
// channel in production. Their DTOs are not process authentication evidence.
// connect-boot supplies TLS inputs, NOT authoritative boot trust. Only a fresh
// ROOT-audited challenge can authorize a result matching those frozen inputs.
import (
	"context"
	"crypto/ed25519"
	c "dev.cengine/guest/internal/storagecontrol"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	p "dev.cengine/guest/internal/storagepki"
)

const lifecycleOperationTimeout = 5 * time.Second

// No process tuple, Guest epoch, key material or receipt is an initialization input.
type lifecycleInitialization struct {
	Binding       a.Fingerprint `json:"binding"`
	ExpectedEpoch uint64        `json:"expected_epoch"`
	IncarnationID string        `json:"incarnation_id"`
	RootPublicKey []byte        `json:"root_public_key"`
	Store         a.ID          `json:"store"`
	Version       string        `json:"version"`
}

func decodeLifecycleInitialization(raw []byte, observed lifecycleProcesses) (lifecycleSessionConfig, error) {
	var init lifecycleInitialization
	if canonical(raw, &init) != nil || init.Version != p.LifecycleChildVersion {
		return lifecycleSessionConfig{}, ErrProtocol
	}
	root, err := p.NewBootstrapPublicKey(ed25519.PublicKey(init.RootPublicKey))
	if err != nil {
		return lifecycleSessionConfig{}, err
	}
	return lifecycleSessionConfig{store: init.Store, binding: init.Binding, expectedEpoch: init.ExpectedEpoch,
		incarnation: init.IncarnationID, root: root, processes: observed}, nil
}

type lifecyclePrivateRequest struct {
	Body      json.RawMessage `json:"body,omitempty"`
	Operation string          `json:"operation"`
	RequestID uint64          `json:"request_id"`
	Version   string          `json:"version"`
}

// The error arm has exactly three fields: never data, a receipt, or an inner
// CONTROL payload. A terminal diagnostic retains its non-nil error: the bridge
// must close after reporting it. Only typed workload failures permit continuation.
func lifecyclePrivateReply(request lifecyclePrivateRequest, data []byte, err error) (any, error) {
	if err != nil {
		if request.Operation != "workload-command" && request.Operation != "connect-workload" {
			return lifecycleTerminalReply(request, err)
		}
		var unavailable *lifecycleWorkloadUnavailable
		var failed *lifecycleWorkloadFailed
		var code string
		switch {
		case errors.As(err, &failed):
			code = "workload-failed"
		case request.Operation == "workload-command" && errors.As(err, &unavailable):
			code = "workload-unavailable"
		default:
			return lifecycleTerminalReply(request, err)
		}
		return lifecyclePrivateErrorReply{code, request.RequestID, request.Version}, nil
	}
	if data == nil {
		data = []byte{}
	}
	return struct {
		Data      []byte `json:"data"`
		RequestID uint64 `json:"request_id"`
		Version   string `json:"version"`
	}{data, request.RequestID, request.Version}, nil
}

type lifecycleBootWire struct {
	CertificateDER []byte                 `json:"certificate_der"`
	Identity       a.LifecycleIdentity    `json:"identity"`
	RootDER        []byte                 `json:"root_der"`
	ServerSPKI     string                 `json:"server_spki"`
	ServiceEpoch   a.ID                   `json:"service_epoch"`
	Signed         a.SignedLifecycleGrant `json:"signed"`
}

func (s *lifecycleSession) decodePrivateBoot(raw []byte) (lifecycleBoot, error) {
	var wire lifecycleBootWire
	if canonical(raw, &wire) != nil {
		return lifecycleBoot{}, ErrProtocol
	}
	root, err := p.ParseRootDER(wire.RootDER)
	if err != nil {
		return lifecycleBoot{}, err
	}
	pinBytes, err := hex.DecodeString(wire.ServerSPKI)
	if err != nil || len(pinBytes) != 32 || hex.EncodeToString(pinBytes) != wire.ServerSPKI {
		return lifecycleBoot{}, ErrProtocol
	}
	var pin p.Fingerprint
	copy(pin[:], pinBytes)
	g := s.greeting.Fields()
	binding, err := p.NewControllerBinding(p.StoreID(g.Store), p.ControllerEpoch(g.ExpectedEpoch+1))
	if err != nil {
		return lifecycleBoot{}, err
	}
	certificate, err := p.ParseCertificateDER(wire.CertificateDER, binding)
	if err != nil {
		return lifecycleBoot{}, err
	}
	return lifecycleBoot{identity: wire.Identity, signed: wire.Signed, serviceEpoch: wire.ServiceEpoch,
		root: root, serverPin: pin, certificate: certificate}, nil
}

// Ownership of stream transfers even on rejection. This closed switch has no
// proof/sign/result/receipt operation or key import/export. Only the nested
// workload union admits Query, always through the v3 current-controller client.
func (s *lifecycleSession) privateLifecycleRequest(ctx context.Context, request lifecyclePrivateRequest, stream net.Conn) (data []byte, err error) {
	if stream != nil {
		defer func() {
			if err != nil {
				stream.Close()
			}
		}()
	}
	if ctx == nil || ctx.Err() != nil || request.Version != p.LifecycleChildVersion || request.RequestID == 0 || (stream != nil) != lifecycleStreamOperation(request.Operation) {
		return nil, ErrProtocol
	}
	ctx, cancel := context.WithTimeout(ctx, lifecycleOperationTimeout)
	defer cancel()
	switch request.Operation {
	case "controller-csr":
		if len(request.Body) != 0 {
			return nil, ErrProtocol
		}
		return s.controllerCSR()
	case "bind-grant", "bind-retire":
		var signed a.SignedLifecycleGrant
		if canonical(request.Body, &signed) != nil {
			return nil, ErrProtocol
		}
		if request.Operation == "bind-retire" {
			return nil, s.bindRetire(signed)
		}
		return nil, s.bindGrant(signed)
	case "connect-boot":
		boot, err := s.decodePrivateBoot(request.Body)
		if err != nil {
			return nil, err
		}
		return nil, s.connectTrustedBoot(ctx, stream, boot)
	case "stage-service-rebind":
		var body struct {
			Boot   lifecycleBootWire               `json:"boot"`
			Change p.LifecycleServiceChangeRequest `json:"change"`
		}
		if canonical(request.Body, &body) != nil || body.Change.Validate() != nil {
			return nil, ErrProtocol
		}
		encoded, err := canonicalBytes(body.Boot)
		if err != nil {
			return nil, err
		}
		boot, err := s.decodePrivateBoot(encoded)
		if err != nil {
			return nil, err
		}
		return nil, s.stageServiceRebind(ctx, stream, body.Change, boot)
	case "connect-workload":
		if len(request.Body) != 0 {
			return nil, ErrProtocol
		}
		return nil, s.connectWorkload(ctx, stream)
	case "attachment-certificate":
		var requestBody LifecycleAttachmentCertificateRequest
		if lifecycleCanonical(request.Body, &requestBody, MaximumPayload) != nil {
			return nil, ErrProtocol
		}
		reply, err := s.attachmentCertificate(ctx, stream, requestBody)
		if err != nil {
			return nil, err
		}
		return canonicalBytes(reply)
	case "workload-command":
		var command c.Request
		if lifecycleCanonical(request.Body, &command, lifecycleWorkloadRequestLimit) != nil {
			return nil, ErrProtocol
		}
		return s.workloadCommand(ctx, command)
	case "public-takeover-replay":
		return s.publicTakeoverReplay(ctx, request.Body)
	case "takeover", "retire":
		if len(request.Body) != 0 {
			return nil, ErrProtocol
		}
		if request.Operation == "retire" {
			return nil, s.retire(ctx)
		}
		return nil, s.takeover(ctx)
	default:
		return nil, ErrProtocol
	}
}
