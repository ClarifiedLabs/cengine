package workloadstorage

import (
	"strconv"

	"dev.cengine/guest/internal/storagefuse"
	"dev.cengine/guest/internal/supervisor"
)

type prepareFailureStage uint8

const (
	prepareSpecification prepareFailureStage = iota
	prepareCompatibility
	prepareWorkload
	prepareNormalObservation
)

func (stage prepareFailureStage) name() string {
	switch stage {
	case prepareSpecification:
		return "specification"
	case prepareCompatibility:
		return "compatibility"
	case prepareWorkload:
		return "workload"
	case prepareNormalObservation:
		return "normal-observation"
	default:
		return "other"
	}
}

// Called synchronously at the original rejection, before the error reply and
// Session teardown. Production installs only the bounded guest-console sink.
// All fields are closed tokens; no cause.Error(), paths or request data escape.
func (s *Session) reportPrepareFailure(stage prepareFailureStage, err error) {
	if s.prepareFailureSink == nil {
		return
	}
	_, category := storagefuse.MountFailureDiagnostic(err)
	line := "cengine managed-prepare-failure stage=" + stage.name() +
		" step=" + supervisor.PrepareFailureStage(err) + " category=" + category
	if op := supervisor.ManagedCopyOperation(err); op != "" {
		line += " op=" + op
	}
	if category == "EACCES" {
		d := s.prepareDenialDiagnosticDetails()
		line += " origin=" + d.Origin + " denials=" + strconv.FormatUint(d.Count, 10) +
			" action=" + d.Action + " fuse=" + d.Operation +
			" begun=" + strconv.FormatBool(d.Begun) + " readOnly=" + strconv.FormatBool(d.ReadOnly) +
			" processStage=" + d.ProcessStage + " processCategory=" + d.ProcessCategory
	}
	s.prepareFailureSink(line)
}

// prepareDenialDiagnostic reads the closed EACCES origin token from the prepare
// attachment's mount, if it is still installed. It is corroborating diagnostic
// evidence only; absence never changes rejection, retry or retirement behavior.
func (s *Session) prepareDenialDiagnostic() (string, uint64) {
	d := s.prepareDenialDiagnosticDetails()
	return d.Origin, d.Count
}

func (s *Session) prepareDenialDiagnosticDetails() storagefuse.PrepareDenialDetails {
	absent := storagefuse.PrepareDenialDetails{Origin: "none", Action: "none", Operation: "other", ProcessStage: "none", ProcessCategory: "unavailable"}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, entry := range s.entries {
		if entry.slot.Role != "prepare" || entry.attachment == nil {
			continue
		}
		if diagnostic, ok := entry.attachment.(interface {
			PrepareDenialDiagnosticDetails() storagefuse.PrepareDenialDetails
		}); ok {
			return diagnostic.PrepareDenialDiagnosticDetails()
		}
		if diagnostic, ok := entry.attachment.(interface {
			PrepareDenialDiagnostic() (string, uint64)
		}); ok {
			absent.Origin, absent.Count = diagnostic.PrepareDenialDiagnostic()
			return absent
		}
	}
	return absent
}
