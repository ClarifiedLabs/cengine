//go:build cengine_prepare_early_compat

package workloadstorage

import (
	"errors"
	"net"
	"testing"

	pc "dev.cengine/guest/internal/preparecompat"
	a "dev.cengine/guest/internal/storageauthority"
)

type earlyObservationGate struct {
	net.Conn
	entered chan struct{}
	release chan struct{}
	fail    bool
}

func (c *earlyObservationGate) Write(raw []byte) (int, error) {
	if len(raw) > 4 {
		frame, err := Decode(raw[4:])
		if err == nil && frame.Operation == "prepare-early-checkpoint" {
			close(c.entered)
			<-c.release
			if c.fail {
				return 0, errors.New("early-observer-write")
			}
		}
	}
	return c.Conn.Write(raw)
}

// The TLS test covers actual five-byte writes; this separately joins the actual
// Session observer, with the witness installed from all actual issued leaves.
func TestEarlyA3JoinsActualSessionObserverWrite(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "written", true: "write-error"}[fail], func(t *testing.T) {
			var factory *earlyFactoryTest
			gate := &earlyObservationGate{entered: make(chan struct{}), release: make(chan struct{}), fail: fail}
			h, _, arm := compatibilityHarness(t, func(h *sessionHarness) {
				factory = &earlyFactoryTest{sessionFactoryFake: h.factory}
				h.s.factory = factory
				h.w.prepareEntered = make(chan struct{})
				h.wrap = func(conn net.Conn) net.Conn { gate.Conn = conn; return gate }
			})
			arm.Version, arm.Profile, arm.CaseName = 2, pc.EarlyProfile, "data-partial-frame"
			h.success("prepare-compatibility-arm", Payload{CompatibilityArm: &arm})
			h.success("mount-phase", Payload{Role: ptr("prepare")})
			entry := h.s.entries[arm.TargetAttachment]
			var credential pc.Credential
			for _, c := range arm.Credentials {
				if c.Attachment == arm.TargetAttachment {
					credential = c
				}
			}
			live := a.DataHello{Epoch: a.ID(arm.Scope.ServiceEpoch), Binding: a.Binding{
				Store: a.ID(arm.Scope.Store), Volume: a.ID(entry.slot.Volume), Attachment: a.ID(entry.slot.Attachment),
				Prepare: a.ID(arm.Scope.Prepare), Container: a.ContainerID(arm.Scope.Container), Launch: a.ID(arm.Scope.Launch),
				Key: a.Fingerprint(credential.Key), Role: a.PrepareRole, Mode: a.ReadWrite,
			}}
			sendCompatibilityPrepare(t, h)
			<-h.w.prepareEntered
			if err := factory.witness.ClaimPartialData(live, entry.identity.Certificate().DER()); err != nil {
				t.Fatal(err)
			}
			joined := make(chan error, 1)
			go func() { joined <- factory.witness.PartialDataWritten(23) }()
			<-gate.entered
			select {
			case <-joined:
				t.Fatal("returned before actual observer write")
			default:
			}
			close(gate.release)
			if !fail {
				frame, err := ReadFrame(h.client)
				if err != nil || frame.Operation != "prepare-early-checkpoint" || frame.Data.CompatibilityEarlyObservation == nil || frame.Data.CompatibilityEarlyObservation.RequestSequence != 23 {
					t.Fatal("actual observer event", err)
				}
			}
			if err := <-joined; err == nil {
				t.Fatal("early became success")
			}
			if factory.witness.NormalObservationWritten() {
				t.Fatal("early became normal completion")
			}
			_ = h.client.Close()
			if err := h.finish(); err == nil {
				t.Fatal("armed early PREPARE succeeded")
			}
		})
	}
}
