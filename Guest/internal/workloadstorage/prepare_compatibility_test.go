package workloadstorage

import (
	"context"
	"crypto/sha256"
	"dev.cengine/guest/internal/preparecompat"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"testing"
)

// These tests cover the real Session and issued leaf certificates, not copy-up,
// FUSE, durability, or VM completion. No fake publication is claimed.
type compatibilityWorkloadTest struct {
	*sessionWorkloadFake
	witness     *preparecompat.Witness
	observation *preparecompat.Observation
}

func (w *compatibilityWorkloadTest) installPrepareCompatibility(v *preparecompat.Witness) error {
	w.witness = v
	return nil
}

func (w *compatibilityWorkloadTest) Prepare(ctx context.Context, raw []byte, claim string, scope Scope, mounts []MountBinding, slots []Slot) error {
	if err := w.sessionWorkloadFake.Prepare(ctx, raw, claim, scope, mounts, slots); err != nil {
		return err
	}
	if w.observation != nil {
		return w.witness.PublishAndHold(*w.observation)
	}
	return nil
}
func compatibilityHarness(t *testing.T, options ...func(*sessionHarness)) (*sessionHarness, *compatibilityWorkloadTest, preparecompat.Arm) {
	h := newSessionHarness(t, 2)
	for i := range *h.config.Data.Mounts {
		(*h.config.Data.Mounts)[i].NoCopy = false
	}
	workload := &compatibilityWorkloadTest{sessionWorkloadFake: h.w}
	h.s.workload = workload
	for _, option := range options {
		option(h)
	}
	h.configure()
	offers := h.offer("prepare")
	credentials := []preparecompat.Credential{}
	for _, offer := range offers {
		der := h.certificate(offer, h.issuer)
		sum := sha256.Sum256(der)
		credentials = append(credentials, preparecompat.Credential{Attachment: offer.Attachment, Key: offer.Key, CertificateSHA256: hex.EncodeToString(sum[:])})
		h.success("install-certificate", Payload{Attachment: &offer.Attachment, CertificateDER: &der})
	}
	arm := preparecompat.Arm{Version: 1, Profile: preparecompat.Profile, RequestID: sessionUUID(t), CaseName: "normal", TargetAttachment: offers[0].Attachment, Binding: preparecompat.BootBinding(h.config.Binding), Scope: preparecompat.Scope(*h.config.Scope), Mounts: compatibilityMounts(*h.config.Data.Mounts), Slots: compatibilitySlots(*h.config.Data.Slots), Credentials: credentials}
	return h, workload, arm
}
func TestCompatibilityArmActualSession(t *testing.T) {
	h, workload, arm := compatibilityHarness(t)
	reply := h.exchange("prepare-compatibility-arm", Payload{CompatibilityArm: &arm})
	if !preparecompat.Enabled() {
		if reply.Data.Code == nil || h.finish() == nil {
			t.Fatal("ordinary accepted arm")
		}
		return
	}
	digest, _ := preparecompat.ArmDigest(arm)
	if reply.Data.CompatibilityDigest == nil || *reply.Data.CompatibilityDigest != digest {
		t.Fatal("ack")
	}
	observation := compatibilityTestObservation(t, arm)
	workload.observation = &observation
	h.success("mount-phase", Payload{Role: ptr("prepare")})
	sendCompatibilityPrepare(t, h)
	checkpoint, err := ReadFrame(h.client)
	if err != nil || checkpoint.Operation != "prepare-checkpoint" || checkpoint.Data.CompatibilityObservation == nil || *checkpoint.Data.CompatibilityObservation != observation {
		t.Fatal("normal checkpoint must precede reply", err)
	}
	reply, err = ReadFrame(h.client)
	if err != nil || reply.Operation != "reply" || reply.Kind != "prepare" || reply.Data.Code != nil || reply.Data.Succeeded == nil || !*reply.Data.Succeeded {
		t.Fatal("normal prepare reply", err)
	}
	h.success("close-phase", Payload{Role: ptr("prepare")})
}
func TestCompatibilityArmRejectsActualMismatch(t *testing.T) {
	if !preparecompat.Enabled() {
		t.Skip("enabled carrier only")
	}
	for name, mutate := range map[string]func(*preparecompat.Arm){"key": func(a *preparecompat.Arm) { a.Credentials[0].Key = strings.Repeat("9", 64) }, "leaf": func(a *preparecompat.Arm) { a.Credentials[0].CertificateSHA256 = strings.Repeat("9", 64) }, "unrelated-runtime": func(a *preparecompat.Arm) {
		for i := range a.Slots {
			if a.Slots[i].Role == "runtime" {
				a.Slots[i].Attachment = sessionUUID(t)
				break
			}
		}
	}, "unrelated-mount": func(a *preparecompat.Arm) { a.Mounts[1].Destination = "/changed" }} {
		t.Run(name, func(t *testing.T) {
			h, _, arm := compatibilityHarness(t)
			mutate(&arm)
			reply := h.exchange("prepare-compatibility-arm", Payload{CompatibilityArm: &arm})
			if reply.Data.Code == nil || h.finish() == nil || len(h.factory.all()) != 0 {
				t.Fatal("invalid arm side effect")
			}
		})
	}
}
func TestCompatibilityArmDuplicateAndWrongPhase(t *testing.T) {
	if !preparecompat.Enabled() {
		t.Skip("enabled carrier only")
	}
	for _, phase := range []string{"duplicate", "mounted"} {
		t.Run(phase, func(t *testing.T) {
			h, _, arm := compatibilityHarness(t)
			if phase == "duplicate" {
				h.success("prepare-compatibility-arm", Payload{CompatibilityArm: &arm})
			} else {
				h.success("mount-phase", Payload{Role: ptr("prepare")})
			}
			if h.exchange("prepare-compatibility-arm", Payload{CompatibilityArm: &arm}).Data.Code == nil || h.finish() == nil {
				t.Fatal("phase accepted")
			}
		})
	}
}

// Exercise only the real Session's nonterminal transport while its PREPARE call
// is pending. This is a DTO transport test, not a fabricated physical copy.
type compatibilityFailObservationConn struct {
	net.Conn
	attempted chan struct{}
}

func (c *compatibilityFailObservationConn) Write(b []byte) (int, error) {
	if len(b) > 4 {
		f, err := Decode(b[4:])
		if err == nil && f.Operation == "prepare-checkpoint" {
			close(c.attempted)
			return 0, errors.New("observer-write")
		}
	}
	return c.Conn.Write(b)
}
func TestCompatibilityObservationIndependentOfPrepareAndCancellation(t *testing.T) {
	if !preparecompat.Enabled() {
		t.Skip("enabled carrier only")
	}
	for _, failWrite := range []bool{false, true} {
		t.Run(map[bool]string{false: "forward", true: "failed-write"}[failWrite], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			attempted := make(chan struct{})
			h, workload, arm := compatibilityHarness(t, func(h *sessionHarness) {
				h.ctx = ctx
				h.w.prepareEntered = make(chan struct{})
				if failWrite {
					h.wrap = func(c net.Conn) net.Conn { return &compatibilityFailObservationConn{Conn: c, attempted: attempted} }
				}
			})
			arm.CaseName = "first-child-published"
			h.success("prepare-compatibility-arm", Payload{CompatibilityArm: &arm})
			h.success("mount-phase", Payload{Role: ptr("prepare")})
			h.seq++
			command := NewFrame("command", h.config.Binding, *h.config.Scope, Payload{WorkloadJSON: &h.raw, IOClaim: ptr("claim")})
			command.Kind = "prepare"
			command.Sequence = &h.seq
			if WriteFrame(h.client, command) != nil {
				t.Fatal("prepare send")
			}
			<-h.w.prepareEntered
			digest, _ := preparecompat.ArmDigest(arm)
			identity := func(inode uint64, kind uint32, handle string) preparecompat.ObjectIdentity {
				return preparecompat.ObjectIdentity{Inode: inode, Generation: 7, FileType: kind, Handle: handle}
			}
			observation := preparecompat.Observation{Version: 1, Profile: preparecompat.Profile, RequestID: arm.RequestID, ArmDigest: digest, Stage: "first-child-published", Count: 1, TargetAttachment: arm.TargetAttachment, CopyIntent: sessionUUID(t), FilesystemUUID: strings.Repeat("1", 32), ManifestDigest: strings.Repeat("a", 64), ManifestSize: 100, Root: identity(1, 16384, "0100000007000000"), Transaction: identity(2, 16384, "0200000007000000"), Published: identity(3, 32768, "0300000007000000"), Staged: identity(4, 32768, "0400000007000000")}
			returned := make(chan error, 1)
			go func() { returned <- workload.witness.PublishAndHold(observation) }()
			if failWrite {
				<-attempted
				h.s.writeMu.Lock()
				h.s.writeMu.Unlock()
			} else {
				frame, err := ReadFrame(h.client)
				if err != nil || frame.Operation != "prepare-checkpoint" || frame.Kind != "" || frame.Sequence != nil || frame.Binding != h.config.Binding || *frame.Scope != *h.config.Scope || frame.Data.CompatibilityObservation == nil || *frame.Data.CompatibilityObservation != observation {
					t.Fatal("independent checkpoint", err)
				}
			}
			if ctx.Err() != nil {
				t.Fatal("observer canceled owner")
			}
			select {
			case <-h.result:
				t.Fatal("PREPARE returned before cancellation")
			default:
			}
			cancel()
			if h.finish() == nil {
				t.Fatal("owner cancellation accepted as success")
			}
			select {
			case <-returned:
				t.Fatal("observer cancellation released hold")
			default:
			}
		})
	}
}

func compatibilityTestObservation(t *testing.T, arm preparecompat.Arm) preparecompat.Observation {
	t.Helper()
	digest, err := preparecompat.ArmDigest(arm)
	if err != nil {
		t.Fatal(err)
	}
	identity := func(n uint64, kind uint32, handle string) preparecompat.ObjectIdentity {
		return preparecompat.ObjectIdentity{Inode: n, Generation: 7, FileType: kind, Handle: handle}
	}
	return preparecompat.Observation{SourceAtimes: preparecompat.SourceAtimes{Root: 7, A: 11, Z: 13}, Version: 1, Profile: preparecompat.Profile, RequestID: arm.RequestID, ArmDigest: digest, Stage: "first-child-published", Count: 1, TargetAttachment: arm.TargetAttachment, CopyIntent: sessionUUID(t), FilesystemUUID: strings.Repeat("1", 32), ManifestDigest: strings.Repeat("a", 64), ManifestSize: 100, Root: identity(1, 16384, "0100000007000000"), Transaction: identity(2, 16384, "0200000007000000"), Published: identity(3, 32768, "0300000007000000"), Staged: identity(4, 32768, "0400000007000000")}
}
func sendCompatibilityPrepare(t *testing.T, h *sessionHarness) {
	t.Helper()
	h.seq++
	frame := NewFrame("command", h.config.Binding, *h.config.Scope, Payload{WorkloadJSON: &h.raw, IOClaim: ptr("claim")})
	frame.Kind = "prepare"
	frame.Sequence = &h.seq
	if err := WriteFrame(h.client, frame); err != nil {
		t.Fatal(err)
	}
}
func TestCompatibilityNormalMissingOrFailedObservationCannotSucceed(t *testing.T) {
	if !preparecompat.Enabled() {
		t.Skip("enabled carrier only")
	}
	for _, missing := range []bool{true, false} {
		t.Run(map[bool]string{true: "missing", false: "failed-write"}[missing], func(t *testing.T) {
			attempted := make(chan struct{})
			h, workload, arm := compatibilityHarness(t, func(h *sessionHarness) {
				if !missing {
					h.wrap = func(c net.Conn) net.Conn { return &compatibilityFailObservationConn{Conn: c, attempted: attempted} }
				}
			})
			h.success("prepare-compatibility-arm", Payload{CompatibilityArm: &arm})
			if !missing {
				observation := compatibilityTestObservation(t, arm)
				workload.observation = &observation
			}
			h.success("mount-phase", Payload{Role: ptr("prepare")})
			reply := h.exchange("prepare", Payload{WorkloadJSON: &h.raw, IOClaim: ptr("claim")})
			if reply.Data.Code == nil || *reply.Data.Code != "prepare" || h.finish() == nil {
				t.Fatal("observation failure became PREPARE success")
			}
		})
	}
}

// Observe entry into the real connection write without replacing or releasing
// it. Cancellation must fail the normal write/prepare, not synthesize success.
type compatibilityObservedWriteConn struct {
	net.Conn
	entered chan struct{}
}

func (c *compatibilityObservedWriteConn) Write(b []byte) (int, error) {
	if len(b) > 4 {
		f, err := Decode(b[4:])
		if err == nil && f.Operation == "prepare-checkpoint" {
			close(c.entered)
		}
	}
	return c.Conn.Write(b)
}
func TestCompatibilityNormalCanceledObservationWriteCannotSucceed(t *testing.T) {
	if !preparecompat.Enabled() {
		t.Skip("enabled carrier only")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{})
	h, workload, arm := compatibilityHarness(t, func(h *sessionHarness) {
		h.ctx = ctx
		h.wrap = func(c net.Conn) net.Conn { return &compatibilityObservedWriteConn{Conn: c, entered: entered} }
	})
	h.success("prepare-compatibility-arm", Payload{CompatibilityArm: &arm})
	observation := compatibilityTestObservation(t, arm)
	workload.observation = &observation
	h.success("mount-phase", Payload{Role: ptr("prepare")})
	sendCompatibilityPrepare(t, h)
	<-entered // net.Pipe's observation body has no reader and cannot finish yet.
	if workload.witness.NormalObservationWritten() {
		t.Fatal("incomplete observation write acknowledged")
	}
	cancel()
	if h.finish() == nil || workload.witness.NormalObservationWritten() {
		t.Fatal("canceled write became PREPARE success")
	}
}
