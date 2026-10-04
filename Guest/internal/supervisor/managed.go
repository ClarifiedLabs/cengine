package supervisor

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"dev.cengine/guest/internal/preparecompat"
	"dev.cengine/guest/internal/protocol"
)

// ManagedMount is a nonsecret mount binding. Mode is the workload's requested
// read-only/read-write mode, including during the read-write prepare phase.
type ManagedMount struct {
	Index                                          uint32
	Volume, Attachment, Destination, Subpath, Mode string
	NoCopy                                         bool
}

type ManagedPlan struct {
	Container, Prepare, SpecificationDigest string
	Store                                   string
	Mounts                                  []ManagedMount
}

const managedMountRoot = "/run/cengine/managed"

// managedState is accessed only under Supervisor.lifecycleMu. Keeping the
// identity/sequence checks independent of Linux makes them natively testable.
type managedState struct {
	compatibility                                           *preparecompat.Witness
	boot, configured, attempted, prepared, started, stopped bool
	identity                                                []byte
	plan                                                    ManagedPlan
	failure                                                 error
}

func (m *managedState) configure() error {
	if m.configured {
		return errors.New("managed supervisor is already configured")
	}
	m.configured = true
	return nil
}

func (m *managedState) beginPrepare(spec protocol.WorkloadSpec, plan ManagedPlan) (bool, error) {
	if !m.configured {
		return false, errors.New("managed supervisor is not configured")
	}
	if m.stopped {
		return false, errors.New("managed supervisor is stopped")
	}
	identity, err := json.Marshal(struct {
		Spec protocol.WorkloadSpec
		Plan ManagedPlan
	}{spec, plan})
	if err != nil {
		return false, err
	}
	if m.attempted {
		if !bytes.Equal(m.identity, identity) {
			return false, errors.New("managed prepare identity changed")
		}
		if m.failure != nil {
			return false, m.failure
		}
		if !m.prepared {
			return false, errors.New("managed prepare did not complete")
		}
		return true, nil
	}
	m.attempted = true
	m.identity = identity
	m.plan = plan
	m.plan.Mounts = append([]ManagedMount(nil), plan.Mounts...)
	if err := validateManagedPlan(spec, plan); err != nil {
		m.failure = err
		return false, err
	}
	return false, nil
}

func rejectManagedAttachments(spec protocol.WorkloadSpec) error {
	for _, mount := range spec.Mounts {
		if mount.ManagedAttachment != "" {
			return errors.New("managedAttachment is reserved for PID1")
		}
	}
	return nil
}

func managedUUID(value string) bool {
	if len(value) != 36 || value[14] != '4' || !strings.ContainsRune("89ab", rune(value[19])) {
		return false
	}
	for i, c := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}

func managedAttachmentPath(attachment string) (string, error) {
	if !managedUUID(attachment) {
		return "", errors.New("managed attachment must be a canonical UUIDv4")
	}
	return managedMountRoot + "/" + attachment + "/root", nil
}

func managedRelativePath(value string) bool {
	if value == "" || len(value) >= 4096 || strings.IndexByte(value, 0) >= 0 {
		return false
	}
	parts := strings.Split(value, "/")
	if len(parts) > 255 {
		return false
	}
	for _, p := range parts {
		if p == "" || p == "." || p == ".." || len(p) > 255 {
			return false
		}
	}
	return true
}

func validateManagedPlan(spec protocol.WorkloadSpec, plan ManagedPlan) error {
	if err := rejectManagedAttachments(spec); err != nil {
		return err
	}
	if plan.Container != spec.ID || !managedRelativePath(plan.Container) || strings.Contains(plan.Container, "/") {
		return errors.New("managed plan container does not match workload")
	}
	if !managedUUID(plan.Prepare) || len(plan.SpecificationDigest) != 64 || strings.Trim(plan.SpecificationDigest, "0123456789abcdef") != "" {
		return errors.New("invalid managed prepare identity")
	}
	if len(spec.Mounts) > 64 || len(plan.Mounts) > 64 {
		return errors.New("too many managed mount bindings")
	}
	indices := map[uint32]bool{}
	volumeAttachments := map[string]string{}
	attachmentVolumes := map[string]string{}
	for _, row := range plan.Mounts {
		if row.Index >= uint32(len(spec.Mounts)) || indices[row.Index] {
			return errors.New("invalid or duplicate managed mount index")
		}
		indices[row.Index] = true
		mount := spec.Mounts[row.Index]
		mode := "read-write"
		if mount.ReadOnly {
			mode = "read-only"
		}
		if mount.Kind != "volume" || mount.Device != "" || mount.Source != row.Volume || mount.Destination != row.Destination || mount.Subpath != row.Subpath || mode != row.Mode || mount.NoCopy != row.NoCopy {
			return fmt.Errorf("managed mount %d does not match workload", row.Index)
		}
		if !managedUUID(row.Volume) || !managedUUID(row.Attachment) || !strings.HasPrefix(row.Destination, "/") || !managedRelativePath(strings.TrimPrefix(row.Destination, "/")) || (row.Subpath != "" && !managedRelativePath(row.Subpath)) {
			return errors.New("invalid managed mount binding")
		}
		if previous := volumeAttachments[row.Volume]; previous != "" && previous != row.Attachment {
			return errors.New("prepare requires one attachment per volume")
		}
		if previous := attachmentVolumes[row.Attachment]; previous != "" && previous != row.Volume {
			return errors.New("prepare attachment reused across volumes")
		}
		volumeAttachments[row.Volume] = row.Attachment
		attachmentVolumes[row.Attachment] = row.Volume
	}
	for index, mount := range spec.Mounts {
		if mount.Kind == "volume" && mount.Device == "" && !indices[uint32(index)] {
			return errors.New("unmapped managed volume mount")
		}
	}
	return nil
}

func runtimeManagedMounts(plan ManagedPlan, mounts []ManagedMount) (map[uint32]string, error) {
	if len(mounts) != len(plan.Mounts) {
		return nil, errors.New("runtime mount count changed")
	}
	byIndex := map[uint32]ManagedMount{}
	prepareAttachments := map[string]bool{}
	for _, mount := range plan.Mounts {
		byIndex[mount.Index] = mount
		prepareAttachments[mount.Attachment] = true
	}
	type slot struct{ volume, mode string }
	slots := map[slot]string{}
	attachments := map[string]slot{}
	result := map[uint32]string{}
	for _, mount := range mounts {
		prepared, ok := byIndex[mount.Index]
		if !ok || result[mount.Index] != "" {
			return nil, errors.New("unknown or duplicate runtime mount")
		}
		attachment := mount.Attachment
		mount.Attachment = prepared.Attachment
		if mount != prepared || !managedUUID(attachment) || prepareAttachments[attachment] {
			return nil, errors.New("runtime mount binding changed or attachment is not fresh")
		}
		key := slot{mount.Volume, mount.Mode}
		if previous := slots[key]; previous != "" && previous != attachment {
			return nil, errors.New("runtime slot has multiple attachments")
		}
		if previous, exists := attachments[attachment]; exists && previous != key {
			return nil, errors.New("runtime attachment reused across slots")
		}
		slots[key] = attachment
		attachments[attachment] = key
		result[mount.Index] = attachment
	}
	return result, nil
}
