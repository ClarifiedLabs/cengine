//go:build cengine_prepare_early_compat

package workloadstorage

import (
	"bufio"
	"context"
	pc "dev.cengine/guest/internal/preparecompat"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

type earlyFactoryTest struct {
	*sessionFactoryFake
	witness *pc.Witness
}

func (f *earlyFactoryTest) installPrepareCompatibility(w *pc.Witness) error {
	f.witness = w
	return nil
}
func TestEarlySessionInstalledFactoryAndRejection(t *testing.T) {
	for _, bad := range []string{"", "key", "certificate", "mount", "slot", "replay"} {
		t.Run(bad, func(t *testing.T) {
			var factory *earlyFactoryTest
			h, workload, arm := compatibilityHarness(t, func(h *sessionHarness) {
				factory = &earlyFactoryTest{sessionFactoryFake: h.factory}
				h.s.factory = factory
			})
			arm.Version, arm.Profile, arm.CaseName = 2, pc.EarlyProfile, "data-partial-frame"
			switch bad {
			case "key":
				arm.Credentials[0].Key = strings.Repeat("9", 64)
			case "certificate":
				arm.Credentials[0].CertificateSHA256 = strings.Repeat("9", 64)
			case "mount":
				arm.Mounts[1].Destination = "/foreign"
			case "slot":
				for i := range arm.Slots {
					if arm.Slots[i].Role == "runtime" {
						arm.Slots[i].Attachment = sessionUUID(t)
						break
					}
				}
			}
			reply := h.exchange("prepare-compatibility-arm", Payload{CompatibilityArm: &arm})
			if bad != "" && bad != "replay" {
				if reply.Data.Code == nil || factory.witness != nil || h.finish() == nil {
					t.Fatal("mismatch installed")
				}
				return
			}
			if reply.Data.CompatibilityDigest == nil || factory.witness == nil || factory.witness != workload.witness {
				t.Fatal("not actual installed witness")
			}
			if bad == "replay" {
				if h.exchange("prepare-compatibility-arm", Payload{CompatibilityArm: &arm}).Data.Code == nil || h.finish() == nil {
					t.Fatal("replay accepted")
				}
				return
			}
			h.success("mount-phase", Payload{Role: ptr("prepare")})
			sendCompatibilityPrepare(t, h)
			reply, err := ReadFrame(h.client)
			if err != nil || reply.Data.Code == nil {
				t.Fatal("early fabricated success", err)
			}
			if h.finish() == nil {
				t.Fatal("early success")
			}
		})
	}
}

// Run the actual permanently parked Session only in a bounded host subprocess.
// The parent observes its typed event then kills and Waits for that exact owner.
func TestEarlySessionA2AcceptedPark(t *testing.T) {
	if os.Getenv("CENGINE_EARLY_A2_CHILD") == "1" {
		h, _, arm := compatibilityHarness(t)
		arm.Version, arm.Profile, arm.CaseName = 2, pc.EarlyProfile, "guest-accepted-before-prepare"
		h.success("prepare-compatibility-arm", Payload{CompatibilityArm: &arm})
		h.success("mount-phase", Payload{Role: ptr("prepare")})
		sendCompatibilityPrepare(t, h)
		event, err := ReadFrame(h.client)
		if err != nil || event.Operation != "prepare-early-checkpoint" || event.Data.CompatibilityEarlyObservation == nil {
			t.Fatal("actual accepted event", err)
		}
		o := event.Data.CompatibilityEarlyObservation
		if o.RequestSequence != h.seq || o.PrepareCommandsAccepted != 1 || o.PrepareCommandsSent != 1 || o.DataBytesWritten != 0 || h.w.prepared.Load() != 0 {
			t.Fatal("wrong cut")
		}
		_ = h.client.Close()
		select {
		case <-h.result:
			t.Fatal("EOF released A2")
		case <-time.After(40 * time.Millisecond):
		}
		if h.w.prepared.Load() != 0 {
			t.Fatal("Prepare invoked")
		}
		_, _ = os.Stdout.WriteString("A2-PARK-VERIFIED\n")
		select {}
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestEarlySessionA2AcceptedPark$")
	cmd.Env = append(os.Environ(), "CENGINE_EARLY_A2_CHILD=1")
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	verified := false
	scanner := bufio.NewScanner(pipe)
	for scanner.Scan() {
		if scanner.Text() == "A2-PARK-VERIFIED" {
			verified = true
			break
		}
	}
	_ = cmd.Process.Kill()
	waitErr := cmd.Wait()
	if !verified || waitErr == nil || ctx.Err() != nil {
		t.Fatal("owner park/containment", verified, waitErr, ctx.Err())
	}
}
func TestEarlyNativeFactorySourceWiring(t *testing.T) {
	raw, err := os.ReadFile("native_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	for _, required := range []string{"f.compatibility.Selected(slot.Attachment)", "witness.ValidateDataAuthority(a.DataHello{Epoch: a.ID(scope.ServiceEpoch), Binding: binding}, identity.Certificate().DER())", "PrepareCompatibility: witness"} {
		if !strings.Contains(source, required) {
			t.Fatal("missing production wiring", required)
		}
	}
	raw, err = os.ReadFile("session.go")
	if err != nil {
		t.Fatal(err)
	}
	source = string(raw)
	validated := strings.Index(source, "SpecificationDigest(raw) != s.scope.SpecificationDigest")
	cut := strings.Index(source, "s.compatibility.AcceptPrepare(s.last)")
	prepare := strings.Index(source, "s.workload.Prepare(ctx,")
	if validated < 0 || cut <= validated || prepare <= cut {
		t.Fatal("A2 moved outside validated actual command")
	}
}
