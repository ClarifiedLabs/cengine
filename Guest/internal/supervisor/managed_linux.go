//go:build linux

package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"dev.cengine/guest/internal/protocol"
	"golang.org/x/sys/unix"
)

// RequireManagedBoot is called only by PID1 after committed container evidence
// and the immutable kernel mode. Image rootfs preparation remains allowed until
// configure, but generic prepare/start must never launch an unowned workload.
func (s *Supervisor) RequireManagedBoot() error {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.managed.boot || s.managed.configured || s.spec != nil || s.command != nil {
		return errors.New("managed boot is already consumed")
	}
	s.managed.boot = true
	return nil
}

// ConfigureManaged permanently disables generic prepare/start/rootfs mutation.
// The caller must authenticate and validate the complete native configuration
// before calling this method. No storage client or credentials enter Supervisor.
func (s *Supervisor) ConfigureManaged() error {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.spec != nil || s.command != nil {
		return errors.New("cannot configure managed storage after workload preparation")
	}
	return s.managed.configure()
}

// WithRootFSPreparation holds the same lifecycle lock throughout rootfs streaming.
func (s *Supervisor) WithRootFSPreparation(prepare func() error) error {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if s.managed.configured {
		return errors.New("rootfs preparation is disabled after managed configuration")
	}
	if prepare == nil {
		return errors.New("rootfs preparation callback is nil")
	}
	return prepare()
}

// PrepareManaged executes copy-up at most once for an exact plan/spec identity.
// The session authenticates the raw specification digest before injecting IOClaim;
// this layer checks the entire decoded mount mapping and owns an immutable copy.
func (s *Supervisor) PrepareManaged(spec protocol.WorkloadSpec, plan ManagedPlan) error {
	return s.PrepareManagedContext(context.Background(), spec, plan)
}

// PrepareManagedContext retains lifecycle ownership while copy-up is in flight.
// Session teardown aborts FUSE to unblock I/O; cancellation is checked before any
// prepared state is committed, without abandoning an unjoined preparation worker.
func (s *Supervisor) PrepareManagedContext(ctx context.Context, spec protocol.WorkloadSpec, plan ManagedPlan) (result error) {
	defer func() { result = WithPrepareFailureStage(PrepareValidation, result) }()
	if err := s.lockLifecycle(ctx); err != nil {
		return err
	}
	defer s.lifecycleMu.Unlock()
	replay, err := s.managed.beginPrepare(spec, plan)
	if err != nil || replay {
		return err
	}
	data, err := json.Marshal(spec)
	var snapshot protocol.WorkloadSpec
	if err == nil {
		err = json.Unmarshal(data, &snapshot)
	}
	spec = snapshot
	if err == nil {
		for _, row := range plan.Mounts {
			spec.Mounts[row.Index].ManagedAttachment = row.Attachment
		}
		err = s.prepareContext(ctx, spec, true)
	}
	if ctx.Err() != nil {
		err = replacePrepareFailureCause(err, ctx.Err())
	}
	if err != nil {
		s.managed.failure = err
		return err
	}
	s.managed.prepared = true
	return nil
}

func (s *Supervisor) StartManaged(mounts []ManagedMount) (protocol.ProcessStatus, error) {
	return s.StartManagedContext(context.Background(), mounts)
}

func (s *Supervisor) StartManagedContext(ctx context.Context, mounts []ManagedMount) (protocol.ProcessStatus, error) {
	if err := s.lockLifecycle(ctx); err != nil {
		// Status takes mu, which an in-flight launch can still own.
		return protocol.ProcessStatus{}, err
	}
	defer s.lifecycleMu.Unlock()
	if !s.managed.configured || !s.managed.prepared || s.managed.failure != nil || s.managed.started || s.managed.stopped {
		return s.Status(), errors.New("managed workload is not startable")
	}
	mapping, err := runtimeManagedMounts(s.managed.plan, mounts)
	if err != nil {
		s.managed.failure = err
		return s.Status(), err
	}
	// Validate every private root before launching; stage-2 pins them again in
	// its inherited namespace. Session retains the mounts until StopManaged.
	for _, attachment := range mapping {
		if err := ctx.Err(); err != nil {
			s.managed.failure = err
			return s.Status(), err
		}
		root, err := openManagedRoot(managedMountRoot, attachment)
		if err != nil {
			s.managed.failure = err
			return s.Status(), err
		}
		root.close()
	}
	s.mu.Lock()
	for index, attachment := range mapping {
		s.spec.Mounts[index].ManagedAttachment = attachment
	}
	s.mu.Unlock()
	s.managed.started = true
	status, err := s.startContext(ctx)
	if err != nil && ctx.Err() != nil {
		err = ctx.Err()
	}
	if err != nil {
		s.managed.failure = err
	}
	return status, err
}

// StopManaged kills only this supervisor's workload cgroup/processes and waits
// for its existing reapers; it never uses wait(-1) or signals PID1/storage peers.
// A deadline leaves the session responsible for retaining its mounts and retrying.
func (s *Supervisor) StopManaged(ctx context.Context) error {
	if err := s.lockLifecycle(ctx); err != nil {
		return err
	}
	defer s.lifecycleMu.Unlock()
	if !s.managed.configured {
		if !s.managed.boot {
			return errors.New("managed supervisor is not configured")
		}
		// Trusted boot may lose its private connection before configuration. Seal
		// it here, under the caller's deadline, instead of re-entering Configure.
		s.managed.configured = true
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	s.managed.stopped = true
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		s.mu.Lock()
		owned := s.command != nil || len(s.execs) != 0
		// Exec starts reserve their status before publishing the command.
		// Retain attachments until those launches either fail or are reaped.
		for _, status := range s.execStatus {
			owned = owned || status.Status == "starting"
		}
		if !owned {
			if s.processIO != nil {
				s.processIO.close()
				s.processIO = nil
			}
			s.mu.Unlock()
			return nil
		}
		// The validated container is a single component, so this cannot target
		// another hierarchy. PID-namespace init death also kills its children.
		if s.spec != nil {
			path := filepath.Join("/sys/fs/cgroup/cengine", s.spec.ID, "cgroup.kill")
			if err := os.WriteFile(path, []byte("1"), 0600); err != nil && !errors.Is(err, os.ErrNotExist) {
				s.mu.Unlock()
				return fmt.Errorf("kill managed workload cgroup: %w", err)
			}
		}
		var killErr error
		if s.command != nil && s.command.Process != nil {
			killErr = s.command.Process.Kill()
		}
		for _, command := range s.execs {
			if command != nil && command.Process != nil {
				if err := command.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) && !errors.Is(err, unix.ESRCH) {
					killErr = err
				}
			}
		}
		s.mu.Unlock()
		if killErr != nil && !errors.Is(killErr, os.ErrProcessDone) && !errors.Is(killErr, unix.ESRCH) {
			return killErr
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// lockLifecycle never starts a detached waiter and never consults process mu.
func (s *Supervisor) lockLifecycle(ctx context.Context) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if s.lifecycleMu.TryLock() {
			if err := ctx.Err(); err != nil {
				s.lifecycleMu.Unlock()
				return err
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func openManagedRoot(base, attachment string) (*confinedRoot, error) {
	if _, err := managedAttachmentPath(attachment); err != nil {
		return nil, err
	}
	parent, err := openConfinedRoot(base)
	if err != nil {
		return nil, err
	}
	defer parent.close()
	fd, err := openConfinedAt(parent.fd, attachment+"/root", unix.O_PATH|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, fmt.Errorf("pin private managed attachment: %w", err)
	}
	return &confinedRoot{fd: fd}, nil
}

func (s *Supervisor) initializeManagedVolume(mount protocol.Mount) error {
	for _, row := range s.managed.plan.Mounts {
		if row.Attachment == mount.ManagedAttachment && row.Volume == mount.Source {
			return initializeManagedVolumeWitnessedAt("/run/cengine/rootfs", managedMountRoot, mount, managedCopyScope{Store: s.managed.plan.Store, Volume: row.Volume, Prepare: s.managed.plan.Prepare, Attachment: row.Attachment}, s.managed.compatibility)
		}
	}
	return errors.New("missing immutable managed copy-up scope")
}

func initializeManagedVolumeAt(rootfs, base string, mount protocol.Mount, checkpoint ...*confinedPublication) error {
	// Retain the direct-filesystem test seam, but never use it as a managed
	// fallback. Production uses initializeManagedVolumeScopedAt exclusively.
	root, err := openManagedRoot(base, mount.ManagedAttachment)
	if err != nil {
		return err
	}
	defer root.close()
	var filesystem unix.Statfs_t
	if err := unix.Fstatfs(root.fd, &filesystem); err != nil {
		return err
	}
	if filesystem.Type == unix.FUSE_SUPER_MAGIC {
		return errors.New("managed copy-up requires immutable expected store/volume scope")
	}
	return initializeVolumeAt(rootfs, procFDRelativePath(root.fd, "."), mount, checkpoint...)
}

func mountManagedVolume(rootfs string, mount protocol.Mount) error {
	root, err := openManagedRoot(managedMountRoot, mount.ManagedAttachment)
	if err != nil {
		return err
	}
	defer root.close()
	return mountConfinedVolume(procFDRelativePath(root.fd, "."), rootfs, mount, unix.Mount, unix.MountSetattr)
}
