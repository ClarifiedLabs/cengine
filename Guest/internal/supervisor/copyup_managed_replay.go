package supervisor

import (
	"errors"

	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
)

// beginManagedCopy performs only private controls. Phase-based recovery and any
// ordinary DATA (even reads) must wait until the exact durable marker is replayed.
// The callback checks immutable launch scope; correlation here also prevents a
// replay response from substituting a different intent, owner, epoch or root.
func beginManagedCopy(call func(w.PrepareRequest) (w.PrepareReply, error), accept func(a.CopyIntent) error) (a.CopyIntent, error) {
	invoke := func(action w.PrepareAction, intent a.ID) (w.PrepareReply, error) {
		if action == w.BeginCopy {
			intent = ""
		}
		request := w.PrepareRequest{Action: action, Intent: intent}
		reply, err := call(request)
		if err == nil {
			err = w.ValidatePrepareReplyFor(request, reply)
		}
		if err == nil {
			err = accept(reply.Intent)
		}
		return reply, err
	}
	reply, err := invoke(w.BeginCopy, "")
	if err != nil {
		return a.CopyIntent{}, err
	}
	if reply.Pending != 0 {
		before, action := reply.Intent, reply.Pending
		reply, err = invoke(action, before.ID)
		if err != nil {
			return a.CopyIntent{}, err
		}
		if reply.Intent.ID != before.ID || reply.Intent.Root != before.Root || reply.Intent.Owner != before.Owner || reply.Intent.Epoch != before.Epoch || reply.Pending != 0 {
			return a.CopyIntent{}, errors.New("managed pending replay changed provenance or remained pending")
		}
		valid := false
		switch action {
		case w.BeginCopy:
			valid = reply.Intent.Phase == before.Phase
		case w.BindCopyTransaction:
			valid = reply.Intent.Phase == a.CopyBound || (before.Phase == a.CopySealed && reply.Intent.Phase == a.CopySealed)
		case w.SealManifest:
			valid = reply.Intent.Phase == a.CopySealed
		case w.StartCleanup:
			valid = reply.Intent.Phase == a.CopyCleaning
		case w.FinishCopy:
			valid = reply.Intent.Phase == a.CopyCompleted
		case w.RollbackCopy:
			valid = reply.Intent.Phase == a.CopyCleaning
		case w.ResumeCopyDirectory:
			valid = reply.Intent == before // only the pending obligation may change
		}
		if !valid {
			return a.CopyIntent{}, errors.New("managed pending operation was not persisted")
		}
		if action == w.FinishCopy || (action == w.ResumeCopyDirectory && reply.Intent.Phase == a.CopyCompleted) {
			// Completed IDs are not replayable. Start a fresh short fence before
			// even probing the volume; never let completion strand initialization.
			reply, err = invoke(w.BeginCopy, "")
			if err != nil {
				return a.CopyIntent{}, err
			}
			if reply.Intent.ID == before.ID || reply.Intent.Root != before.Root || reply.Intent.Owner != before.Owner || reply.Intent.Epoch != before.Epoch {
				return a.CopyIntent{}, errors.New("managed fresh begin changed provenance")
			}
		}
	}
	if reply.Pending != 0 {
		return a.CopyIntent{}, errors.New("managed begin remains pending")
	}
	switch reply.Intent.Phase {
	case a.CopyBegun, a.CopyBound, a.CopySealed, a.CopyCleaning:
		return reply.Intent, nil
	default:
		return a.CopyIntent{}, errors.New("invalid managed copy-up begin phase")
	}
}
