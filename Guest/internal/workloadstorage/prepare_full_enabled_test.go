//go:build cengine_prepare_full_compat && !cengine_prepare_compat && !cengine_prepare_early_compat

package workloadstorage

import (
	"net"
	"strings"
	"testing"

	pc "dev.cengine/guest/internal/preparecompat"
)

type fullFactoryTest struct {
	*sessionFactoryFake
	witness *pc.Witness
}

func (f *fullFactoryTest) installPrepareCompatibility(w *pc.Witness) error { f.witness = w; return nil }
func TestFullA8ActualSessionCompletesPrepareAndClose(t *testing.T) {
	h, workload, arm := compatibilityHarness(t)
	arm.Version = 3
	arm.Profile = pc.FullProfile
	arm.CaseName = "drain-durable-reply-lost"
	h.success("prepare-compatibility-arm", Payload{CompatibilityArm: &arm})
	o := compatibilityTestObservation(t, arm)
	o.Version = 3
	o.Profile = pc.FullProfile
	workload.observation = &o
	h.success("mount-phase", Payload{Role: ptr("prepare")})
	sendCompatibilityPrepare(t, h)
	checkpoint, err := ReadFrame(h.client)
	if err != nil || checkpoint.Operation != "prepare-checkpoint" {
		t.Fatal("A8 physical checkpoint", err)
	}
	reply, err := ReadFrame(h.client)
	if err != nil || reply.Data.Code != nil || reply.Data.Succeeded == nil || !*reply.Data.Succeeded {
		t.Fatal("A8 prepare must complete", err)
	}
	h.success("close-phase", Payload{Role: ptr("prepare")})
	// The actual host Retire route, not a fake guest receipt, owns A8's storage cut.
}
func TestFullCleaningMissedStorageHoldCannotSucceedAfterPhysicalWrite(t *testing.T) {
	for _, outcome := range []string{"written", "missing", "failed-write"} {
		t.Run(outcome, func(t *testing.T) {
			failures := make(chan string, 1)
			h, workload, arm := compatibilityHarness(t, func(h *sessionHarness) {
				// Configure a real single-volume Session before it issues credentials;
				// do not truncate only the signed arm or bypass installed comparison.
				*h.config.Data.Mounts = (*h.config.Data.Mounts)[:1]
				*h.config.Data.Slots = (*h.config.Data.Slots)[:2]
				h.s.prepareFailureSink = func(line string) { failures <- line }
				if outcome == "failed-write" {
					h.wrap = func(c net.Conn) net.Conn {
						return &compatibilityFailObservationConn{Conn: c, attempted: make(chan struct{})}
					}
				}
			})
			arm.Version, arm.Profile, arm.CaseName = 3, pc.FullProfile, "vm-cleaning-transaction-removed"
			h.success("prepare-compatibility-arm", Payload{CompatibilityArm: &arm})
			if !workload.witness.RequiresGuestObservation() {
				t.Fatal("CLEANING missing independent physical observer")
			}
			o := compatibilityTestObservation(t, arm)
			o.Version, o.Profile = 3, pc.FullProfile
			if outcome != "missing" {
				workload.observation = &o
			}
			h.success("mount-phase", Payload{Role: ptr("prepare")})
			sendCompatibilityPrepare(t, h)
			if outcome == "written" {
				checkpoint, err := ReadFrame(h.client)
				if err != nil || checkpoint.Operation != "prepare-checkpoint" || checkpoint.Data.CompatibilityObservation == nil || *checkpoint.Data.CompatibilityObservation != o {
					t.Fatal("CLEANING physical write", err)
				}
			}
			reply, err := ReadFrame(h.client)
			if err != nil || reply.Data.Code == nil || *reply.Data.Code != "prepare" || reply.Data.Succeeded != nil || workload.witness.NormalObservationWritten() || h.finish() == nil {
				t.Fatal("missed CLEANING hold became PREPARE success", err)
			}
			want := "stage=normal-observation"
			if outcome == "failed-write" {
				want = "stage=workload"
			}
			if got := <-failures; !strings.Contains(got, want) {
				t.Fatal("wrong rejection gate", got)
			}
		})
	}
}

func TestFullStorageCutsNoGuestObserverAndNoSuccessFallback(t *testing.T) {
	for _, name := range []string{"full-frame-before-admit", "admitted-queued", "transaction-published-bind-reply-lost"} {
		t.Run(name, func(t *testing.T) {
			h, workload, arm := compatibilityHarness(t)
			arm.Version = 3
			arm.Profile = pc.FullProfile
			arm.CaseName = name
			h.success("prepare-compatibility-arm", Payload{CompatibilityArm: &arm})
			if workload.witness.RequiresGuestObservation() {
				t.Fatal("missing-observer wait")
			}
			h.success("mount-phase", Payload{Role: ptr("prepare")})
			reply := h.exchange("prepare", Payload{WorkloadJSON: &h.raw, IOClaim: ptr("claim")})
			if reply.Data.Code == nil || *reply.Data.Code != "prepare" || h.finish() == nil {
				t.Fatal("missed storage hook became success")
			}
		})
	}
}
func TestFullArmCompleteInstalledCredentialComparison(t *testing.T) {
	for _, bad := range []string{"", "key", "leaf", "unrelated-slot", "unrelated-mount", "duplicate"} {
		t.Run(bad, func(t *testing.T) {
			var factory *fullFactoryTest
			h, workload, arm := compatibilityHarness(t, func(h *sessionHarness) {
				factory = &fullFactoryTest{sessionFactoryFake: h.factory}
				h.s.factory = factory
			})
			arm.Version = 3
			arm.Profile = pc.FullProfile
			arm.CaseName = "data-partial-frame"
			switch bad {
			case "key":
				arm.Credentials[0].Key = strings.Repeat("9", 64)
			case "leaf":
				arm.Credentials[0].CertificateSHA256 = strings.Repeat("9", 64)
			case "unrelated-slot":
				for i := range arm.Slots {
					if arm.Slots[i].Role == "runtime" {
						arm.Slots[i].Attachment = sessionUUID(t)
						break
					}
				}
			case "unrelated-mount":
				arm.Mounts[1].Destination = "/foreign"
			}
			reply := h.exchange("prepare-compatibility-arm", Payload{CompatibilityArm: &arm})
			if bad != "" && bad != "duplicate" {
				if reply.Data.Code == nil || factory.witness != nil || h.finish() == nil {
					t.Fatal("mismatch installed")
				}
				return
			}
			if reply.Data.CompatibilityDigest == nil || factory.witness == nil || factory.witness != workload.witness {
				t.Fatal("actual A3 factory witness missing")
			}
			if bad == "duplicate" {
				if h.exchange("prepare-compatibility-arm", Payload{CompatibilityArm: &arm}).Data.Code == nil || h.finish() == nil {
					t.Fatal("duplicate arm")
				}
			}
		})
	}
}
