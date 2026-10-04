//go:build linux

package supervisor

import "golang.org/x/sys/unix"

// managedCopyIO is private, invocation-local routing, not a filesystem emulator.
// A nil callback always performs the real operation. Only an authenticated,
// selected workload IO witness is bound in production; errno/checkpoint ownership
// stays in Witness.InjectIO, including its full signed-owner and first-hit checks.
type managedCopyIO func(point string) error

func (copy *managedCopy) compatibilityIO() managedCopyIO {
	if copy.compatibility == nil || !copy.compatibility.IsWorkloadIO() || !copy.compatibility.Selected(copy.scope.Attachment) {
		return nil
	}
	return func(point string) error {
		return copy.compatibility.InjectIO(point, copy.intent)
	}
}

func (cut managedCopyIO) before(point string) error {
	if cut == nil {
		return nil
	}
	return cut(point)
}

func (cut managedCopyIO) childSync() func(string) error {
	if cut == nil {
		return nil
	}
	return func(relative string) error {
		if relative != "a" {
			return nil
		}
		return cut.before("child-data-fsync")
	}
}

// Reopen the pinned directory before offering the cut: a failed open must not
// claim that fsync was reached. No global/general-purpose fsync hook is used.
func (cut managedCopyIO) syncDirectory(directoryFD int, point string) (result error) {
	stage := manifestDirectoryReopen
	defer func() {
		if point == "manifest-rename-parent-sync" {
			result = wrapManifestFailure(stage, result)
		}
	}()
	fd, err := unix.Openat(directoryFD, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	stage = manifestDirectoryCut
	if err := cut.before(point); err != nil {
		return err
	}
	stage = manifestDirectorySync
	return unix.Fsync(fd)
}
