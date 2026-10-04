package storagefuse

// Closed local diagnostic vocabulary; never contains proc data or numeric IDs.
type processMatchStage uint8

const (
	matchNone processMatchStage = iota
	matchUnavailable
	matchClosed
	matchZeroTID
	matchNoOwner
	matchFirstPoll
	matchFirstReady
	matchFinalPoll
	matchFinalReady
	matchLeaderRead
	matchLeaderParse
	matchLeaderStart
	matchMemberDir
	matchMemberStatus
	matchMemberTGIDParse
	matchMemberTGIDMismatch
	matchMemberStatRead
	matchMemberStatParse
)

func (s processMatchStage) name() string {
	switch s {
	case matchNone:
		return "none"
	case matchClosed:
		return "closed"
	case matchZeroTID:
		return "zero-tid"
	case matchNoOwner:
		return "no-owner"
	case matchFirstPoll:
		return "first-pidfd-poll"
	case matchFirstReady:
		return "first-pidfd-ready"
	case matchFinalPoll:
		return "final-pidfd-poll"
	case matchFinalReady:
		return "final-pidfd-ready"
	case matchLeaderRead:
		return "leader-stat-read"
	case matchLeaderParse:
		return "leader-stat-parse"
	case matchLeaderStart:
		return "leader-start-mismatch"
	case matchMemberDir:
		return "member-dir"
	case matchMemberStatus:
		return "member-status-read"
	case matchMemberTGIDParse:
		return "member-tgid-parse"
	case matchMemberTGIDMismatch:
		return "member-tgid-mismatch"
	case matchMemberStatRead:
		return "member-stat-read"
	case matchMemberStatParse:
		return "member-stat-parse"
	default:
		return "unavailable"
	}
}

type processMatchFailure struct {
	stage processMatchStage
	cause error
}

func (f processMatchFailure) diagnostic() (string, string) {
	category := "unavailable"
	if f.cause != nil {
		category = mountFailureCategory(f.cause)
	}
	return f.stage.name(), category
}

// Pure classification of already-obtained results: no retries or new syscalls.
func processPollFailure(final bool, n int, revents int16, err error) processMatchFailure {
	if err != nil {
		if final {
			return processMatchFailure{matchFinalPoll, err}
		}
		return processMatchFailure{matchFirstPoll, err}
	}
	if n != 0 || revents != 0 {
		if final {
			return processMatchFailure{stage: matchFinalReady}
		}
		return processMatchFailure{stage: matchFirstReady}
	}
	return processMatchFailure{}
}

func processStatFailure(leader bool, start, expected uint64, ok bool, err error) processMatchFailure {
	if err != nil {
		if leader {
			return processMatchFailure{matchLeaderRead, err}
		}
		return processMatchFailure{matchMemberStatRead, err}
	}
	if !ok {
		if leader {
			return processMatchFailure{stage: matchLeaderParse}
		}
		return processMatchFailure{stage: matchMemberStatParse}
	}
	if leader && start != expected {
		return processMatchFailure{stage: matchLeaderStart}
	}
	return processMatchFailure{}
}

func processMemberFailure(tgid, expected uint32, ok bool, err error) processMatchFailure {
	if err != nil {
		return processMatchFailure{matchMemberStatus, err}
	}
	if !ok {
		return processMatchFailure{stage: matchMemberTGIDParse}
	}
	if tgid != expected {
		return processMatchFailure{stage: matchMemberTGIDMismatch}
	}
	return processMatchFailure{}
}
