//go:build linux || darwin

package storageauthority

import (
	"encoding/json"
	"os"

	"golang.org/x/sys/unix"
)

// Independent of the public receipt/wire schema. Old journals never established
// this obligation and must not be silently upgraded after a possible IO fault.
const durabilityVersion = 1
const dataIOName = "data-uncertain"
const maxDurabilityBytes = 2048

type durabilityRecord struct {
	Version    int        `json:"version"`
	Epoch      ID         `json:"epoch"`
	Controller Controller `json:"controller"`
	Binding    Binding    `json:"binding"`
	Sequence   uint64     `json:"sequence"`
}

type durabilityToken struct {
	guard     *guardToken
	completed bool
}

// DurabilityObligation is sealed to one live accepted request. It is not a drain
// receipt. The trusted managed dispatcher must complete it only after syscall,
// ordered filesystem synchronization, and reply/event validation. No timeout or
// Guard.Release implies completion; a copied token cannot clear a later request.
type DurabilityObligation struct{ token *durabilityToken }

// BeginDurability must precede any mutation or flush/close barrier. The managed
// service's global namespace gate serializes these bounded (single-slot) records.
// Ordinary reads do not call this API. The journal lock protects the slot across
// processes; control-state commits and retirement use different marker names.
func (g *Guard) BeginDurability(sequence uint64) (*DurabilityObligation, error) {
	if g == nil || g.token == nil || g.token.owner == nil || sequence == 0 {
		return nil, ErrUnauthorized
	}
	t := g.token
	a := t.owner
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.available(); err != nil {
		return nil, err
	}
	if t.released || t.epoch != a.s.Epoch {
		return nil, ErrClosed
	}
	rec, ok := a.s.Attachments[t.binding.Attachment]
	if !ok || rec.Binding != t.binding || (rec.Phase != Active && rec.Phase != Retiring) {
		return nil, ErrUnauthorized
	}
	if a.copyReplayPending(t.binding.Volume) {
		return nil, ErrBlocked
	}
	if a.dataIO != nil || a.copyIO != nil {
		return nil, ErrBusy
	}
	record := durabilityRecord{durabilityVersion, a.s.Epoch, a.s.Controller, t.binding, sequence}
	if err := a.j.beginDataIO(record); err != nil {
		return nil, a.poison(err)
	}
	token := &durabilityToken{guard: t}
	a.dataIO = token
	return &DurabilityObligation{token}, nil
}

func (d *DurabilityObligation) Complete(cause error) error {
	if d == nil || d.token == nil || d.token.guard == nil {
		return ErrUnauthorized
	}
	t := d.token
	a := t.guard.owner
	a.mu.Lock()
	defer a.mu.Unlock()
	if t.completed || a.dataIO != t || t.guard.released {
		return ErrClosed
	}
	if err := a.available(); err != nil {
		return err
	}
	if cause != nil {
		return a.poison(cause)
	}
	if err := a.j.clearDataIO(); err != nil {
		return a.poison(err)
	}
	t.completed = true
	a.dataIO = nil
	return nil
}

func (j *journal) beginDataIO(record durabilityRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if len(data) > maxDurabilityBytes {
		return ErrLimit
	}
	var f *os.File
	if err = j.step("data-open", func() (e error) {
		f, e = child(j.dir, dataIOName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0600)
		return
	}); err != nil {
		return err
	}
	defer f.Close()
	if err = j.step("data-write", func() error { return writeFull(f, data) }); err != nil {
		return err
	}
	if err = j.step("data-sync", f.Sync); err != nil {
		return err
	}
	if err = j.step("data-close", f.Close); err != nil {
		return err
	}
	return j.step("data-parent-sync", j.dir.Sync)
}
func (j *journal) clearDataIO() error {
	if err := j.step("data-unlink", func() error { return unix.Unlinkat(int(j.dir.Fd()), dataIOName, 0) }); err != nil {
		return err
	}
	return j.step("data-clear-sync", j.dir.Sync)
}
