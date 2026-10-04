package diskbootstrap

import (
	"fmt"
	"io"
)

func blockIdentifier(ordinal int) string {
	if ordinal == 0 {
		return "root"
	}
	return fmt.Sprintf("volume%d", ordinal-1)
}

type target struct{ device, destination, label string }

func diskTarget(kind string, d ManifestDisk) target {
	if kind == "storage" {
		return target{"/dev/vda", "/data", "cengine-volumes"}
	}
	if d.Ordinal == 0 {
		return target{"/dev/vda", "/run/cengine/rootfs", "cengine-root"}
	}
	return target{fmt.Sprintf("/dev/vd%c", 'a'+d.Ordinal), "/run/cengine/volumes/" + *d.VolumeName, "cengine-volume"}
}

type identity struct {
	uuid  string
	bytes uint64
}
type diskOperations interface {
	prepare([]target) error
	initialize(target, string, uint64) error
	mount(target) error
	sync(target) (identity, error)
}

// A separate seam prevents older operations implementations from silently
// treating a probe as an unrestricted mount.
type readOnlyOperations interface {
	probeReadOnly(target, string, uint64) (identity, error)
}

// validateManifest is deliberately complete and side-effect free. No directory,
// mount, or formatter operation can run until the entire batch is accepted.
func validateManifest(h Hello, m Manifest) error {
	if !validMessage(&h) || !validMessage(&m) || h.Type != "hello" || m.Type != "manifest" ||
		m.Kind != h.Kind || m.GuestBootNonce != h.GuestBootNonce || len(m.Disks) != len(h.Disks) {
		return failure("invalid-manifest", nil)
	}
	for i, d := range m.Disks {
		if d.ExpectedBytes != h.Disks[i].Bytes {
			return failure("disk-mismatch", &d.Ordinal)
		}
	}
	return nil
}

// session owns exactly one manifest. Failure (including a lost commit) is terminal.
// Only returning nil authorizes PID1 to create its ordinary service listeners.
func session(rw io.ReadWriter, h Hello, ops diskOperations) error {
	_, err := sessionEvidence(rw, h, ops)
	return err
}

func sessionEvidence(rw io.ReadWriter, h Hello, ops diskOperations) (evidence *Synced, err error) {
	defer func() {
		if err != nil {
			f, ok := err.(*Failure)
			if !ok {
				f = failure("invalid-frame", nil)
			}
			_ = WriteFrame(rw, f)
		}
	}()
	if err := WriteFrame(rw, &h); err != nil {
		return nil, failure("invalid-frame", nil)
	}
	message, err := ReadFrame(rw)
	if err != nil {
		return nil, failure("invalid-frame", nil)
	}
	m, ok := message.(*Manifest)
	if !ok {
		return nil, failure("invalid-manifest", nil)
	}
	if err := validateManifest(h, *m); err != nil {
		return nil, err
	}
	targets := make([]target, len(m.Disks))
	for i, d := range m.Disks {
		targets[i] = diskTarget(m.Kind, d)
	}
	if err := ops.prepare(targets); err != nil {
		if f, ok := err.(*Failure); ok && f.Code == "disk-mismatch" {
			return nil, failure("disk-mismatch", nil)
		}
		return nil, failure("disk-operation", nil)
	}
	ack := Synced{Version: Version, Type: "synced", ShimLaunchUUID: m.ShimLaunchUUID, GuestBootNonce: h.GuestBootNonce, Sync: "filesystem-and-block", Disks: make([]SyncedDisk, 0, len(m.Disks))}
	for i, d := range m.Disks {
		var observed identity
		if d.Action == "probe-read-only" {
			probe, ok := ops.(readOnlyOperations)
			if !ok {
				return nil, failure("disk-operation", &d.Ordinal)
			}
			observed, err = probe.probeReadOnly(targets[i], *d.Ext4UUID, d.ExpectedBytes)
			if err != nil {
				return nil, failure("disk-operation", &d.Ordinal)
			}
			ack.Sync = "read-only-no-replay"
		} else {
			if d.Action == "initialize-ext4" {
				err = ops.initialize(targets[i], *d.Ext4UUID, d.ExpectedBytes)
			} else {
				err = ops.mount(targets[i])
			}
			if err != nil {
				return nil, failure("disk-operation", &d.Ordinal)
			}
			observed, err = ops.sync(targets[i])
			if err != nil {
				return nil, failure("sync", &d.Ordinal)
			}
		}
		if !validUUID(observed.uuid) || observed.bytes != d.ExpectedBytes || (d.Ext4UUID != nil && observed.uuid != *d.Ext4UUID) {
			return nil, failure("disk-mismatch", &d.Ordinal)
		}
		ack.Disks = append(ack.Disks, SyncedDisk{Ordinal: d.Ordinal, Bytes: observed.bytes, Ext4UUID: observed.uuid, OperationUUID: d.OperationUUID})
	}
	if err := WriteFrame(rw, &ack); err != nil {
		return nil, failure("sync", nil)
	}
	message, err = ReadFrame(rw)
	if err != nil {
		return nil, failure("commit", nil)
	}
	commit, ok := message.(*Commit)
	if !ok || commit.ShimLaunchUUID != m.ShimLaunchUUID || commit.GuestBootNonce != h.GuestBootNonce {
		return nil, failure("commit", nil)
	}
	return &ack, nil
}
