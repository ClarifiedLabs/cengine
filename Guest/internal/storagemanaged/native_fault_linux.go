//go:build cengine_native_faulttest && linux && (arm64 || amd64)

package storagemanaged

import (
	a "dev.cengine/guest/internal/storageauthority"
)

// NativeFaultCounter is observation only; no reset/rearm or force-drain API.
type NativeFaultCounter struct{ witness *a.NativeFaultWitness }

func (c *NativeFaultCounter) Count() uint32                         { return c.witness.Observation().Fired }
func (c *NativeFaultCounter) Observation() a.NativeFaultObservation { return c.witness.Observation() }

// InstallNativeFault must run on a fresh registry before any DATA traffic. Every
// unselected syscall remains real, including syncfs after namespace failure.
func (r *Registry) InstallNativeFault(witness *a.NativeFaultWitness) (*NativeFaultCounter, error) {
	p := witness.Plan()
	if err := p.Validate(); err != nil {
		return nil, err
	}
	r.gate.Lock()
	defer r.gate.Unlock()
	if len(r.sessions) != 0 || r.worker != nil || r.postNamespace != nil {
		return nil, a.ErrConflict
	}
	counter := &NativeFaultCounter{witness}
	fail := witness.DataFault
	realSyncfs := r.syncOps.syncfs
	r.syncOps.syncfs = func(fd int) error {
		// Authority selection may precede acquisition of this gate. Only the
		// exact Barrier currently executing under it can consume final-sync
		// injection; another volume's syscall must remain real while it waits.
		if r.barrierBinding == nil || !p.Matches(*r.barrierBinding) {
			return realSyncfs(fd)
		}
		// The selected barrier must also have closed all its volume's sessions,
		// handles, metadata capabilities and object pins before final syncfs.
		closed := true
		for b := range r.sessions {
			if b.Volume == p.Volume {
				closed = false
			}
		}
		for key := range r.objects {
			if key.volume == p.Volume {
				closed = false
			}
		}
		if closed {
			if err := witness.FinalSyncFault(*r.barrierBinding); err != nil {
				return err
			}
		}
		return realSyncfs(fd)
	}
	// Reserve the otherwise nil seam for all stages to reject a second install.
	r.postNamespace = func() error {
		if p.Stage == a.NativePostCreateNamespace {
			return fail()
		}
		return nil
	}
	if p.Stage == a.NativeDataFsync {
		real := r.syncOps.fsync
		r.syncOps.fsync = func(fd int) error {
			if err := fail(); err != nil {
				return err
			}
			return real(fd)
		}
	}
	return counter, nil
}
