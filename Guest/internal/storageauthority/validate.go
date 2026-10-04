package storageauthority

import (
	"encoding/hex"
	"fmt"
	"reflect"
)

// Validate semantic relationships as well as JSON shape. A corrupt or newer
// registry is never reinterpreted as an empty registry or a drain receipt.
func (a *Authority) validate() error {
	s := a.s
	fail := func(why string) error { return fmt.Errorf("%w: %s", ErrInvalid, why) }
	if s.Schema != LifecycleSchemaVersion || s.Durability != durabilityVersion || s.Revision == 0 || !validID(s.Store.ID) || !validID(s.Epoch) || s.Controller.Epoch == 0 || !validKey(s.Controller.Key) || !validKey(s.Bootstrap) {
		return fail("header")
	}
	if s.Volumes == nil || s.VolumeLifecycles == nil || len(s.VolumeLifecycles) != len(s.Volumes) || s.Attachments == nil || s.Prepares == nil || s.Operations == nil {
		return fail("missing tables")
	}
	l := a.limits
	if len(s.Volumes) > l.Volumes || len(s.Attachments) > l.Attachments || len(s.Prepares) > l.Prepares || len(s.Operations) > l.Operations {
		return ErrLimit
	}
	keys := map[Fingerprint]bool{s.Bootstrap: true}
	if err := a.validateLifecycle(); err != nil {
		return err
	}
	keys[s.Controller.Key] = true
	names := map[string]bool{}
	roots := map[RootIdentity]bool{}
	for id, v := range s.Volumes {
		life := s.VolumeLifecycles[id]
		if err := a.validateVolume(v, life); err != nil {
			return err
		}
		if life.Phase == VolumeCreating {
			v.Root = RootIdentity{Device: s.Store.Root.Device, Inode: 1}
		}
		if id != v.ID || !volumeValid(v) || v.Root.Device != s.Store.Root.Device || (life.Phase != VolumeDeleted && (names[v.Name] || (life.Phase != VolumeCreating && roots[v.Root]))) {
			return fail("volume binding")
		}
		if life.Phase != VolumeDeleted {
			names[v.Name] = true
			if life.Phase != VolumeCreating {
				roots[v.Root] = true
			}
		}
	}
	for id, rec := range s.Attachments {
		b := rec.Binding
		if s.VolumeLifecycles[b.Volume].Phase != VolumeReady && rec.Phase != Drained {
			return fail("nonready volume authority")
		}
		if id != b.Attachment || !bindingValid(b, s) || keys[b.Key] {
			return fail("attachment binding")
		}
		keys[b.Key] = true
		if _, ok := s.Volumes[b.Volume]; !ok {
			return fail("attachment volume")
		}
		if rec.Retirement != "" {
			want := digest("retire", RetireRequest{rec.Retirement, b.Store, b.Volume, id, b.Launch})
			if !validID(rec.Retirement) || s.Operations[rec.Retirement] != want || (rec.Phase != Retiring && rec.Phase != Drained) {
				return fail("retirement operation")
			}
		} else if rec.Phase == Drained {
			return fail("receipt without retirement intent")
		}
		switch rec.Phase {
		case Reserved, Active, Retiring:
			if rec.Receipt != nil {
				return fail("premature receipt")
			}
		case Drained:
			r := rec.Receipt
			if r == nil || r.Schema != SchemaVersion || r.Store != b.Store || r.Volume != b.Volume || r.Attachment != id || r.Launch != b.Launch || r.Prepare != b.Prepare || r.Revision == 0 || r.Revision > s.Revision {
				return fail("receipt binding")
			}
		default:
			return fail("attachment phase")
		}
		if b.Role == PrepareRole {
			p, ok := s.Prepares[b.Prepare]
			if !ok {
				return fail("missing prepare")
			}
			found := false
			for _, planned := range p.Attachments {
				if planned == b {
					found = true
				}
			}
			if !found {
				return fail("unplanned attachment")
			}
		} else if rec.Phase == Reserved {
			return fail("reserved runtime")
		}
	}
	pending := map[ID]bool{}
	for id, p := range s.Prepares {
		if !validID(id) || id != p.ID || len(p.Attachments) == 0 || !reflect.DeepEqual(p.Attachments, canonicalReserve(ReserveRequest{Attachments: p.Attachments}).Attachments) {
			return fail("prepare identity/order")
		}
		if c := p.Context; (s.Lifecycle == nil) != (c == nil) || c != nil && (!validID(c.ServiceEpoch) || c.ControllerEpoch == 0 ||
			c.ControllerEpoch > s.Controller.Epoch || !validKey(c.ControllerKey) || c.ControllerKey == s.Bootstrap ||
			c.ControllerEpoch == s.Controller.Epoch && c.ControllerKey != s.Controller.Key) {
			return fail("prepare context")
		}
		vols := map[ID]bool{}
		for _, b := range p.Attachments {
			rec, ok := s.Attachments[b.Attachment]
			if !ok || b.Role != PrepareRole || b.Prepare != id || rec.Binding != b || vols[b.Volume] {
				return fail("prepare plan")
			}
			vols[b.Volume] = true
			if p.Phase == Pending {
				if s.VolumeLifecycles[b.Volume].Phase != VolumeReady {
					return fail("nonready prepared volume")
				}
				if pending[b.Volume] {
					return fail("overlapping prepares")
				}
				pending[b.Volume] = true
			} else if rec.Phase != Drained {
				return fail("undrained terminal prepare")
			}
		}
		switch p.Phase {
		case Pending:
			if p.Successor != "" || p.Attestation != nil {
				return fail("pending prepare")
			}
		case Completed:
			if p.Successor != "" || p.Attestation == nil || *p.Attestation != (Attestation{id, true, true}) {
				return fail("completion attestation")
			}
		case Replaced:
			successor, ok := s.Prepares[p.Successor]
			if !ok || p.Successor == id || p.Attestation != nil || len(successor.Attachments) != len(p.Attachments) {
				return fail("successor")
			}
			for i, b := range p.Attachments {
				if successor.Attachments[i].Volume != b.Volume {
					return fail("successor volume set")
				}
			}
		default:
			return fail("prepare phase")
		}
	}
	for id, op := range s.Operations {
		b, err := hex.DecodeString(op.Digest)
		if !validID(id) || err != nil || len(b) != 32 {
			return fail("operation identity")
		}
		switch op.Kind {
		case "create-volume", "delete-volume", "volume", "reserve", "register", "retire", "complete", "replace":
		default:
			return fail("operation kind")
		}
	}
	return a.validateCopyState()
}
