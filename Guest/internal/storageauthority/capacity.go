package storageauthority

import "encoding/json"

// Reserve ledger slots and sufficient encoded receipt space BEFORE exposing any
// new attachment or PREPARE. Limits stop new growth, not the first retirement
// of existing A or completion of an admitted P after its exact drained receipts.
// This is a logical budget, not a guarantee against physical ENOSPC during fsync.
func (a *Authority) capacity(s *diskState, bytes int64) error {
	operations := len(s.Operations)
	// Leave a revision for each outstanding receipt and, when not yet recorded,
	// its retirement intent. Even revision exhaustion must not strand admitted A.
	var revisions uint64
	// V2 reserves its irreversible intent and terminal result, independently of
	// the v1 operation ledger. Completed takeovers consume no history slots.
	if s.Lifecycle != nil && s.Lifecycle.Seal == nil {
		bytes += 2048
		revisions++
		if s.Lifecycle.Retiring == nil {
			revisions++
		}
	}
	// A future service revision can grow to 20 decimal digits.
	bytes += 32
	// A reconstructed operation contains another complete fixed-size CopyIntent.
	// Keep one maximum replay slot per copy volume, subtracting its actual encoded
	// use. Completed intents retain the slot for a fresh Begin's pre-commit crash.
	replayVolumes := map[ID]bool{}
	if s.Copy != nil {
		for volume := range s.Copy.Intents {
			replayVolumes[volume] = true
		}
	}
	for volume := range s.CopyReplay {
		replayVolumes[volume] = true
	}
	if a.copyIO != nil {
		replayVolumes[a.copyIO.record.Binding.Volume] = true
	}
	if len(s.CopyReplay) != 0 {
		encoded, _ := json.Marshal(s.CopyReplay)
		bytes -= int64(len(encoded) + len(`,"copy_replay":`))
	}
	for volume := range replayVolumes {
		bytes += maxCopyOperationBytes + 128
		active := a.copyIO != nil && a.copyIO.record.Binding.Volume == volume
		switch {
		case active && a.copyIO.clearingReplay:
			// The candidate state has already consumed its clear revision.
		case active && !a.copyIO.reusesReplay:
			revisions += 2 // one crash startup and exact replay's ledger clear
		default:
			if _, ok := s.CopyReplay[volume]; ok {
				revisions++ // successful exact replay clears the existing entry
			}
		}
	}
	if s.Copy != nil {
		for _, intent := range s.Copy.Intents {
			// Reserve the maximum fixed DTO encoding, not manifest bytes. Five
			// revisions cover initial metadata, bind, seal, cleaning, completion.
			if intent.Phase != CopyCompleted {
				before, _ := json.Marshal(intent)
				maximum := maxCopyIntent(intent)
				after, _ := json.Marshal(maximum)
				bytes += int64(len(after) - len(before))
			}
			switch intent.Phase {
			case CopyBegun:
				revisions += 4
				if !intent.InitialCaptured {
					revisions++
				}
			case CopyBound:
				revisions += 3
			case CopySealed:
				revisions += 2
			case CopyCleaning:
				revisions++
			}
		}
	}
	for _, life := range s.VolumeLifecycles {
		if life.Phase == VolumeCreating || life.Phase == VolumeDeleting {
			revisions++
			// Root device/inode, terminal phase and uint64 revision growth.
			// Completion reuses the already-reserved operation slot.
			bytes += 128
		}
	}
	for _, prep := range s.Prepares {
		if prep.Phase != Pending {
			continue
		}
		operations++
		revisions++
		before, _ := json.Marshal(prep)
		// COMPLETED plus its fixed attestation is larger than REPLACED plus a
		// successor UUID. Replacement must separately fund its fresh successor;
		// this reservation pays only for resolving the existing P.
		prep.Phase = Completed
		prep.Attestation = &Attestation{prep.ID, true, true}
		after, _ := json.Marshal(prep)
		// Includes the map key/separator and fixed kind/SHA256 operation entry.
		bytes += 160 + int64(len(after)-len(before))
	}
	for _, rec := range s.Attachments {
		if rec.Phase == Drained {
			continue
		}
		revisions++
		before, _ := json.Marshal(rec)
		if rec.Retirement == "" {
			revisions++
			operations++
			rec.Retirement = ID("00000000-0000-4000-8000-000000000000")
			// The operation map entry (UUID, fixed kind, SHA256 digest) is <160B.
			bytes += 160
		}
		rec.Phase = Drained
		b := rec.Binding
		rec.Receipt = &Receipt{SchemaVersion, b.Store, b.Volume, b.Attachment, b.Launch, b.Prepare, ^uint64(0)}
		after, _ := json.Marshal(rec)
		bytes += int64(len(after) - len(before))
	}
	if operations > a.limits.Operations || bytes > a.limits.JournalBytes || revisions > ^uint64(0)-s.Revision {
		return ErrLimit
	}
	return nil
}

// Each numeric field has its widest legal encoding. This is only a byte budget,
// not valid identity evidence; the actual ledger always stores real objects.
func maxCopyIntent(i CopyIntent) CopyIntent {
	o := Ext4ObjectV1{Inode: uint64(^uint32(0)), Generation: ^uint32(0), FileType: 0100000, HandleType: 1, HandleSize: 8, Handle: [8]byte{255, 255, 255, 255, 255, 255, 255, 255}}
	c := CopyCleanupV1{UID: ^uint32(0), GID: ^uint32(0), Mode: 07777, ATimeSeconds: -1 << 63, MTimeSeconds: -1 << 63, ATimeNanos: 999999999, MTimeNanos: 999999999, Manifest: o, Staging: o}
	i.Initial = c
	i.Initial.Manifest, i.Initial.Staging = Ext4ObjectV1{}, Ext4ObjectV1{}
	i.InitialCaptured = true
	i.Cleanup, i.Transaction = c, o
	i.ManifestDigest = [32]byte{}
	for j := range i.ManifestDigest {
		i.ManifestDigest[j] = 255
	}
	i.ManifestSize, i.Phase = MaxCopyManifestBytes, CopyCompleted
	return i
}
