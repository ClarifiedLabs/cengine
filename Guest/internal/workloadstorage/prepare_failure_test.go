package workloadstorage

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"dev.cengine/guest/internal/preparecompat"
	"dev.cengine/guest/internal/storagefuse"
	"dev.cengine/guest/internal/supervisor"
	"golang.org/x/sys/unix"
)

type prepareReplyOrderConn struct {
	net.Conn
	reported *atomic.Bool
	bad      *atomic.Bool
}

func (c *prepareReplyOrderConn) Write(b []byte) (int, error) {
	if len(b) > 4 {
		f, err := Decode(b[4:])
		if err == nil && f.Operation == "reply" && f.Kind == "prepare" && !c.reported.Load() {
			c.bad.Store(true)
		}
	}
	return c.Conn.Write(b)
}

func TestPrepareFailureActualSessionBeforeReplyAndCleanup(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		cause                 error
		stage, step, category string
	}{
		{"errno", &os.PathError{Op: "SECRET", Path: "/SECRET\nspoof", Err: unix.EIO}, "workload", "other", "EIO"},
		{"opaque", unprintableAttachmentError{}, "workload", "other", "other"},
		{"supervisor", supervisor.WithPrepareFailureStage(supervisor.PrepareManagedCopyUp, &os.PathError{Op: "SECRET", Path: "/SECRET", Err: unix.ENOSPC}), "workload", "managed-copyup", "ENOSPC"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newSessionHarness(t, 1)
			h.w.prepareError = tc.cause
			var reported, bad atomic.Bool
			lines := make(chan string, 2)
			h.s.prepareFailureSink = func(line string) {
				if h.w.stopped.Load() != 0 {
					bad.Store(true)
				}
				for _, a := range h.factory.all() {
					if a.aborted.Load() != 0 {
						bad.Store(true)
					}
				}
				lines <- line
				reported.Store(true)
			}
			h.wrap = func(conn net.Conn) net.Conn { return &prepareReplyOrderConn{conn, &reported, &bad} }
			h.configure()
			h.mount("prepare")
			raw := h.raw
			reply := h.exchange("prepare", Payload{WorkloadJSON: &raw, IOClaim: ptr("SECRET")})
			if reply.Data.Code == nil || *reply.Data.Code != "prepare" {
				t.Fatal("rejection changed")
			}
			if h.finish() == nil {
				t.Fatal("failed prepare accepted")
			}
			want := "cengine managed-prepare-failure stage=" + tc.stage + " step=" + tc.step + " category=" + tc.category
			if len(lines) != 1 || <-lines != want || !reported.Load() || bad.Load() {
				t.Fatal("diagnostic content/order changed")
			}
			if (tc.stage == "workload") != (h.w.prepared.Load() == 1) {
				t.Fatal("workload admission changed")
			}
		})
	}
}

func TestPrepareFailureCompatibilityAndObservationActualSession(t *testing.T) {
	if !preparecompat.FullEnabled() {
		t.Skip("full compatibility carrier only")
	}
	for _, name := range []string{"compatibility", "normal-observation"} {
		t.Run(name, func(t *testing.T) {
			lines := make(chan string, 1)
			h, _, arm := compatibilityHarness(t, func(h *sessionHarness) { h.s.prepareFailureSink = func(line string) { lines <- line } })
			arm.Version, arm.Profile = 3, preparecompat.FullProfile
			if name == "compatibility" {
				arm.CaseName = "before-prepare-send"
			}
			h.success("prepare-compatibility-arm", Payload{CompatibilityArm: &arm})
			h.success("mount-phase", Payload{Role: ptr("prepare")})
			reply := h.exchange("prepare", Payload{WorkloadJSON: &h.raw, IOClaim: ptr("SECRET")})
			if reply.Data.Code == nil || *reply.Data.Code != "prepare" || h.finish() == nil {
				t.Fatal("invalid prepare accepted")
			}
			if len(lines) != 1 || <-lines != "cengine managed-prepare-failure stage="+name+" step=other category=other" {
				t.Fatal("wrong boundary diagnostic")
			}
			if (name == "normal-observation") != (h.w.prepared.Load() == 1) {
				t.Fatal("workload admission changed")
			}
		})
	}
}

func TestPrepareFailureClosedVocabularyAndProductionWiring(t *testing.T) {
	for stage := prepareFailureStage(0); ; stage++ {
		var line string
		s := &Session{prepareFailureSink: func(v string) { line = v }}
		cause := errors.Join(unprintableAttachmentError{}, context.Canceled)
		s.reportPrepareFailure(stage, cause)
		if !strings.HasPrefix(line, "cengine managed-prepare-failure stage=") || !strings.HasSuffix(line, " step=other category=canceled") || len(line) > 160 {
			t.Fatal("unbounded diagnostic")
		}
		if stage > prepareNormalObservation && !strings.Contains(line, " stage=other ") {
			t.Fatal("open stage vocabulary")
		}
		if stage == 255 {
			break
		}
	}
	data, err := os.ReadFile("native_linux.go")
	if err != nil || strings.Count(string(data), "session.prepareFailureSink = emitMountFailure") != 1 {
		t.Fatal("production bounded sink not installed")
	}
}

// Wire validation rejects malformed/mismatched specifications even earlier.
// Exercise the Session's independent defense directly, without weakening wire checks.
func TestPrepareFailureSpecificationActualCommand(t *testing.T) {
	for _, raw := range [][]byte{[]byte(`{"ioClaim":"SECRET"}`), []byte(`{"ioClaim":""}`)} {
		h := newSessionHarness(t, 0)
		h.s.phase = "prepare-mounted"
		h.s.scope = *h.config.Scope
		if strings.Contains(string(raw), "SECRET") {
			h.s.scope.SpecificationDigest = SpecificationDigest(raw)
		}
		var lines []string
		h.s.prepareFailureSink = func(line string) { lines = append(lines, line) }
		_, code := h.s.command(context.Background(), "prepare", Payload{WorkloadJSON: &raw, IOClaim: ptr("SECRET")})
		if code != "prepare" || h.w.prepared.Load() != 0 || h.w.stopped.Load() != 0 || len(lines) != 1 || lines[0] != "cengine managed-prepare-failure stage=specification step=other category=other" {
			t.Fatal("specification diagnostic or admission changed")
		}
	}
}

// EACCES failures gain the closed origin/denial suffix read from the prepare
// attachment's mount; non-EACCES categories and absent op tokens stay unchanged.
func TestPrepareFailureEACCESOriginSuffix(t *testing.T) {
	h := newSessionHarness(t, 1)
	h.w.prepareError = supervisor.WithPrepareFailureStage(supervisor.PrepareManagedCopyUp, unix.EACCES)
	lines := make(chan string, 2)
	h.s.prepareFailureSink = func(line string) { lines <- line }
	h.configure()
	h.mount("prepare")
	raw := h.raw
	reply := h.exchange("prepare", Payload{WorkloadJSON: &raw, IOClaim: ptr("SECRET")})
	if reply.Data.Code == nil || *reply.Data.Code != "prepare" || h.finish() == nil {
		t.Fatal("rejection changed")
	}
	// The session harness's fake attachment does not implement the diagnostic
	// interface, so the origin degrades to the closed "none"/0 tokens.
	want := "cengine managed-prepare-failure stage=workload step=managed-copyup category=EACCES origin=none denials=0 action=none fuse=other begun=false readOnly=false processStage=none processCategory=unavailable"
	if len(lines) != 1 || <-lines != want {
		t.Fatal("EACCES origin suffix changed")
	}
}

type detailedDenialAttachment struct {
	Attachment
	details storagefuse.PrepareDenialDetails
}

func (a detailedDenialAttachment) PrepareDenialDiagnosticDetails() storagefuse.PrepareDenialDetails {
	return a.details
}
func (a detailedDenialAttachment) PrepareDenialDiagnostic() (string, uint64) { return "storage", 99 }

type legacyDenialAttachment struct{ Attachment }

func (legacyDenialAttachment) PrepareDenialDiagnostic() (string, uint64) { return "storage", 2 }

func TestPrepareFailureDenialDetails(t *testing.T) {
	details := storagefuse.PrepareDenialDetails{Origin: "gate-order", Count: 1, Action: "identity", Operation: "IOCTL", ReadOnly: true, ProcessStage: "none", ProcessCategory: "unavailable"}
	for _, tc := range []struct {
		name, role string
		attachment Attachment
		suffix     string
	}{
		{"detailed preferred", "prepare", detailedDenialAttachment{details: details}, "origin=gate-order denials=1 action=identity fuse=IOCTL begun=false readOnly=true processStage=none processCategory=unavailable"},
		{"original process failure", "prepare", detailedDenialAttachment{details: storagefuse.PrepareDenialDetails{Origin: "gate-process", Count: 1, Action: "none", Operation: "IOCTL", Begun: true, ProcessStage: "first-pidfd-poll", ProcessCategory: "EINTR"}}, "origin=gate-process denials=1 action=none fuse=IOCTL begun=true readOnly=false processStage=first-pidfd-poll processCategory=EINTR"},
		{"legacy", "prepare", legacyDenialAttachment{}, "origin=storage denials=2 action=none fuse=other begun=false readOnly=false processStage=none processCategory=unavailable"},
		{"runtime ignored", "runtime", detailedDenialAttachment{details: details}, "origin=none denials=0 action=none fuse=other begun=false readOnly=false processStage=none processCategory=unavailable"},
		{"missing attachment", "prepare", nil, "origin=none denials=0 action=none fuse=other begun=false readOnly=false processStage=none processCategory=unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var line string
			s := &Session{entries: map[string]*sessionAttachment{"one": {slot: Slot{Role: tc.role}, attachment: tc.attachment}}, prepareFailureSink: func(v string) { line = v }}
			s.reportPrepareFailure(prepareWorkload, unix.EACCES)
			if want := "cengine managed-prepare-failure stage=workload step=other category=EACCES " + tc.suffix; line != want {
				t.Fatalf("got %q, want %q", line, want)
			}
			s.reportPrepareFailure(prepareWorkload, unix.EIO)
			if line != "cengine managed-prepare-failure stage=workload step=other category=EIO" {
				t.Fatal("non-EACCES changed", line)
			}
		})
	}
}
