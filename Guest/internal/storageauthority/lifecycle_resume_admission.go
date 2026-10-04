package storageauthority

// AdmitLifecycleResumeReadOnly checks ROOT's exact resume request against a
// closed empty layout or the exact unused original genesis registry. It never
// creates, syncs, cleans up, repairs or recovers anything, and returns no live
// authority. An already-applied request returns ErrLifecycleResumeAlreadyApplied,
// not permission to promote the disk.
//
// The caller must hold the exclusive disk.ProbeExt4ReadOnly lease throughout
// this check and its promotion. This result alone is not a disk capability:
// the caller must also authenticate the observed launch and couple successful
// admission to promotion of that same opaque lease, without reopening a path.
func AdmitLifecycleResumeReadOnly(c Config, signed SignedLifecycleResumeOpen) error {
	var err error
	c, err = configured(c)
	if err != nil {
		return err
	}
	pin, err := dupDirectory(c.Root)
	if err != nil {
		return err
	}
	defer pin.Close()
	c.Root = pin
	signed.Signature = append([]byte(nil), signed.Signature...)
	signed.Request.Takeover.Signature = append([]byte(nil), signed.Request.Takeover.Signature...)
	if err = VerifyLifecycleResumeOpen(c.BootstrapKey, signed); err != nil {
		return err
	}
	census, err := probeResumeLayout(pin)
	if err != nil {
		return err
	}
	if census != resumeCensusRegistry {
		return nil
	}
	j, err := probeJournal(c)
	if err != nil {
		return err
	}
	defer j.close()
	s, err := j.load()
	if err != nil {
		return err
	}
	if s.Schema != LifecycleSchemaVersion || s.Lifecycle == nil {
		return ErrInvalid
	}
	r := signed.Request
	root, err := identity(j.root)
	if err != nil {
		return err
	}
	exports, err := identity(j.exports)
	if err != nil {
		return err
	}
	boot, err := PublicKeyFingerprint(c.BootstrapKey)
	if err != nil {
		return err
	}
	if s.Store.ID != r.Original.Identity.Store || s.Store.DeviceID != c.DeviceID ||
		s.Store.Root != root || s.Store.Exports != exports || s.Bootstrap != boot ||
		s.Lifecycle.Identity != r.Original.Identity {
		return ErrConflict
	}
	if s.Lifecycle.Retiring != nil {
		return ErrBlocked
	}
	a := &Authority{s: s, j: j, limits: c.Limits}
	if err = a.validate(); err != nil {
		return err
	}
	return a.admitResumeOpen(r)
}
