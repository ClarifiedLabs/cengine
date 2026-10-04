package storagefuse

import (
	"context"
	"errors"
	"sync"

	c "dev.cengine/guest/internal/storageclient"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// directoryRelease belongs to an actual OPENDIR grant on this raw filesystem.
// done publishes err only after the actual RELEASEDIR callback and native reply
// delivery, or publishes a sticky failure. No synthetic lifecycle request exists.
type directoryRelease struct {
	fh, unique       uint64
	callbackReturned bool
	done             chan struct{}
	err              error // published by closing done
	settled          bool  // protected by directoryReleases.mu
}

type directoryReleases struct {
	mu        sync.Mutex
	limit     int
	handles   map[uint64]*directoryRelease
	requests  map[uint64]*directoryRelease
	opens     map[uint64]bool // admitted OPENDIR Unique -> callback returned
	sealed    bool
	err       error
	completed uint64 // successful native deliveries; bounded scalar, not a log
	changed   chan struct{}
}

func (d *directoryReleases) changedLocked() {
	if d.changed != nil {
		close(d.changed)
	}
	d.changed = make(chan struct{})
}
func (d *directoryReleases) failLocked(err error) error {
	if d.err == nil {
		d.err = errors.Join(errTranslation, err)
		for _, release := range d.handles {
			if !release.settled {
				release.err = d.err
				release.settled = true
				close(release.done)
			}
		}
		d.changedLocked()
	}
	return d.err
}

var errDirectoryAdmissionClosed = errors.New("storagefuse: directory admission closed")

func (d *directoryReleases) beginOpen(unique uint64) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.err != nil {
		return d.err
	}
	if d.sealed {
		return errDirectoryAdmissionClosed
	}
	if unique == 0 {
		return d.failLocked(ErrProfile)
	}
	if _, found := d.opens[unique]; found {
		return d.failLocked(ErrProfile)
	}
	if d.limit <= 0 || len(d.opens)+len(d.handles) >= d.limit {
		return d.failLocked(c.ErrCapacity)
	}
	if d.opens == nil {
		d.opens = make(map[uint64]bool)
	}
	d.opens[unique] = false
	d.changedLocked()
	return nil
}
func (d *directoryReleases) returnedOpen(unique, fh uint64, status fuse.Status) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.err != nil {
		return d.err
	}
	returned, found := d.opens[unique]
	if !found || returned {
		return d.failLocked(ErrProfile)
	}
	if status == fuse.OK {
		if err := d.openedLocked(fh); err != nil {
			return err
		}
	}
	d.opens[unique] = true
	d.changedLocked()
	return nil
}
func (d *directoryReleases) deliveredOpen(reply fuse.ReplyDelivery) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.err != nil {
		return d.err
	}
	returned, found := d.opens[reply.Unique]
	// Rejected post-seal requests never acquired a grant or admission credit.
	if !found && d.sealed && reply.Status == fuse.EBUSY {
		return nil
	}
	expected := 16
	if reply.Status == fuse.OK {
		expected = 32
	}
	if !found || !returned || reply.Opcode != 27 || reply.Err != nil || reply.Suppressed || reply.Status == fuse.EINTR || reply.Bytes != expected || reply.Expected != expected {
		return d.failLocked(reply.Err)
	}
	delete(d.opens, reply.Unique)
	d.changedLocked()
	return nil
}
func (d *directoryReleases) opened(fh uint64) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.openedLocked(fh)
}
func (d *directoryReleases) openedLocked(fh uint64) error {
	if d.err != nil {
		return d.err
	}
	if fh == 0 || d.handles[fh] != nil {
		return d.failLocked(ErrProfile)
	}
	if d.limit <= 0 || len(d.handles) >= d.limit {
		return d.failLocked(c.ErrCapacity)
	}
	if d.handles == nil {
		d.handles = make(map[uint64]*directoryRelease)
		d.requests = make(map[uint64]*directoryRelease)
	}
	d.handles[fh] = &directoryRelease{fh: fh, done: make(chan struct{})}
	d.changedLocked()
	return nil
}
func (d *directoryReleases) releasing(unique, fh uint64) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.err != nil {
		return d.err
	}
	release := d.handles[fh]
	if unique == 0 || release == nil || release.unique != 0 || d.requests[unique] != nil {
		return d.failLocked(ErrProfile)
	}
	release.unique = unique
	d.requests[unique] = release
	d.changedLocked()
	return nil
}
func (d *directoryReleases) returned(unique uint64) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.err != nil {
		return d.err
	}
	release := d.requests[unique]
	if release == nil || release.callbackReturned {
		return d.failLocked(ErrProfile)
	}
	release.callbackReturned = true
	d.changedLocked()
	return nil
}
func (d *directoryReleases) delivered(reply fuse.ReplyDelivery, stopped bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.err != nil {
		return d.err
	}
	release := d.requests[reply.Unique]
	if stopped || release == nil || !release.callbackReturned || reply.Opcode != 29 || reply.Unique == 0 ||
		reply.Status != fuse.OK || reply.Err != nil || reply.Suppressed || reply.Bytes != 16 || reply.Expected != 16 {
		return d.failLocked(reply.Err)
	}
	if d.completed == ^uint64(0) {
		return d.failLocked(c.ErrCapacity)
	}
	delete(d.handles, release.fh)
	delete(d.requests, reply.Unique)
	release.settled = true
	close(release.done)
	d.completed++
	d.changedLocked()
	return nil
}
func (d *directoryReleases) snapshot() ([]*directoryRelease, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.err != nil {
		return nil, d.err
	}
	releases := make([]*directoryRelease, 0, len(d.handles))
	for _, release := range d.handles {
		releases = append(releases, release)
	}
	return releases, nil
}

// Seal only new OPENDIR grants, never RELEASEDIR/FORGET cleanup. Join every
// already admitted OPENDIR callback and native response before the final list.
func (d *directoryReleases) sealAndSnapshot(ctx context.Context, terminal <-chan struct{}) ([]*directoryRelease, error) {
	d.mu.Lock()
	d.sealed = true
	d.changedLocked()
	for {
		if d.err != nil {
			err := d.err
			d.mu.Unlock()
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			d.mu.Unlock()
			return nil, err
		}
		if len(d.opens) == 0 {
			releases := make([]*directoryRelease, 0, len(d.handles))
			for _, release := range d.handles {
				releases = append(releases, release)
			}
			d.mu.Unlock()
			return releases, nil
		}
		changed := d.changed
		d.mu.Unlock()
		select {
		case <-changed:
		case <-terminal:
			return nil, c.ErrClosed
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		d.mu.Lock()
	}
}

func waitDirectoryReleases(ctx context.Context, releases []*directoryRelease, terminal <-chan struct{}) error {
	for _, release := range releases {
		select {
		case <-release.done:
			if release.err != nil {
				return release.err
			}
		case <-terminal:
			return c.ErrClosed
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	select {
	case <-terminal:
		return c.ErrClosed
	default:
		return ctx.Err()
	}
}

func (f *lifecycleFS) OpenDir(cancel <-chan struct{}, in *fuse.OpenIn, out *fuse.OpenOut) fuse.Status {
	defer markCallbackPanic(in.Opcode)
	*out = fuse.OpenOut{}
	if err := f.directories.beginOpen(in.Unique); err != nil {
		if errors.Is(err, errDirectoryAdmissionClosed) {
			return fuse.EBUSY
		}
		f.stopAt(siteDirectoryAdmission, in.Opcode, err)
		return fuse.EIO
	}
	status := f.rawFS.OpenDir(cancel, in, out)
	if err := f.directories.returnedOpen(in.Unique, out.Fh, status); err != nil {
		f.stopAt(siteDirectoryGrant, in.Opcode, err)
		return fuse.EIO
	}
	return status
}
func (f *lifecycleFS) ReleaseDir(in *fuse.ReleaseIn) {
	defer markCallbackPanic(in.Opcode)
	if err := f.directories.releasing(in.Unique, in.Fh); err != nil {
		f.stopAt(siteDirectoryRelease, in.Opcode, err)
		return
	}
	f.rawFS.ReleaseDir(in)
	if err := f.directories.returned(in.Unique); err != nil {
		f.stopAt(siteDirectoryReturn, in.Opcode, err)
	}
}
