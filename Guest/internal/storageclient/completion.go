package storageclient

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"

	w "dev.cengine/guest/internal/storagewire"
)

type completedOutcome uint8

const (
	completedSuccess completedOutcome = iota
	completedFailure
	completedNegative
	completedProbeRetry
)

// Only completed, validated replies reach this policy. Linux getxattr(2) defines
// ENODATA as absence/inaccessibility of an attribute, not a failed mutation.
// getxattr(2)/listxattr(2) define ERANGE as insufficient buffer capacity; require
// an actual successful data retry before allowing graceful completion. Constants
// are Linux wire errno values, including when the client is tested on Darwin.
func classifyCompletedOutcome(body w.RequestBody, errno uint32) completedOutcome {
	if errno == 0 {
		return completedSuccess
	}
	switch request := body.(type) {
	case w.LookupRequest:
		if errno == 2 {
			return completedNegative
		} // ENOENT
	case w.PrepareRequest:
		// Recovery queries both published and staged paths under the authenticated
		// intent/fence; an absent counterpart is a completed negative lookup, not
		// incomplete cleanup. Preserve the ENOENT reply for the identity check.
		// Root absence, other controls and every other error remain failures.
		if request.Action == w.IdentityAt && len(request.Path) != 0 && string(request.Path) != "." && errno == 2 {
			return completedNegative
		}
	case w.GetXAttrRequest:
		if errno == 61 {
			return completedNegative
		} // ENODATA
		if errno == 34 && request.Size != 0 {
			return completedProbeRetry
		} // ERANGE
	case w.ListXAttrRequest:
		if errno == 34 && request.Size != 0 {
			return completedProbeRetry
		}
	}
	return completedFailure
}

// This key holds no authority and never changes grants. Fingerprint the complete
// validated caller (including groups/caps) to avoid retaining a MaxGroups-sized
// credential per probe. IDs are never reused within a client. Sequence and buffer
// size are deliberately excluded: a retry is a new request with a new buffer.
type xattrProbeKey struct {
	operation w.Operation
	node      w.NodeID
	name      string
	caller    [sha256.Size]byte
}

func xattrProbe(req w.Request) (key xattrProbeKey, capacity uint32, ok bool) {
	key.operation = req.Body.Operation()
	switch body := req.Body.(type) {
	case w.GetXAttrRequest:
		key.node, key.name, capacity = body.Node, string(body.Name), body.Size
	case w.ListXAttrRequest:
		key.node, capacity = body.Node, body.Size
	default:
		return key, 0, false
	}
	raw, err := json.Marshal(req.Auth)
	if err != nil {
		return key, 0, false
	}
	key.caller = sha256.Sum256(raw)
	return key, capacity, true
}

// Called under Client.mu after correlation/body validation and before publication
// to the adapter. Probe capacity is bounded independently of live grants; overflow
// is sticky, never eviction or manufactured completion.
func (c *Client) recordCompletedOutcome(req w.Request, reply w.Reply) {
	if c.recordPrepareReadDirRetry(req, reply) {
		return
	}
	switch classifyCompletedOutcome(req.Body, reply.Errno) {
	case completedNegative:
		return
	case completedSuccess:
		if len(c.pendingProbes) != 0 {
			if key, capacity, ok := xattrProbe(req); ok && capacity != 0 {
				delete(c.pendingProbes, key)
			}
		}
		return
	case completedProbeRetry:
		if key, _, ok := xattrProbe(req); ok {
			if _, found := c.pendingProbes[key]; found {
				return
			}
			if len(c.pendingProbes) < c.limits.Requests {
				if c.pendingProbes == nil {
					c.pendingProbes = make(map[xattrProbeKey]struct{})
				}
				c.pendingProbes[key] = struct{}{}
				return
			}
			if c.completionErr == nil {
				c.completionErr = fmt.Errorf("%w: %w: pending xattr size probes", ErrIncomplete, ErrCapacity)
			}
			return
		}
	}
	if c.completionErr == nil {
		c.completionErr = fmt.Errorf("%w: operation %v errno %d", ErrIncomplete, req.Body.Operation(), reply.Errno)
	}
}

var errUnresolvedXattrProbe = fmt.Errorf("%w: unresolved xattr size probe", ErrIncomplete)

// Caller holds Client.mu. Abort/Close must preserve unresolved probe evidence too.
func (c *Client) completionError() error {
	var replay error
	if c.prepareReadDir != nil && len(c.prepareReadDir.queries) != 0 {
		replay = errors.Join(ErrIncomplete, errPrepareReadDirRetry)
	}
	if len(c.pendingProbes) != 0 {
		return errors.Join(c.completionErr, errUnresolvedXattrProbe, replay)
	}
	return errors.Join(c.completionErr, replay)
}
