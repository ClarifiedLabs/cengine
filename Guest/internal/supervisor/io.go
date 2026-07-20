//go:build linux

package supervisor

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

const ioDirectoryPath = "/run/cengine/io"

type pinnedProcessIO struct {
	directory   *os.File
	stdout      *os.File
	stderr      *os.File
	stdin       *os.File
	stdinClosed *os.File
}

func openPinnedProcessIO(directoryPath, prefix, claim string) (*pinnedProcessIO, error) {
	if !validIOClaim(claim) {
		return nil, errors.New("I/O claim is invalid")
	}
	names := []string{
		prefix + "stdout",
		prefix + "stderr",
		prefix + "stdin",
		prefix + "stdin.closed",
	}
	for _, name := range names {
		if name == "" || name == "." || name == ".." || filepath.Base(name) != name {
			return nil, fmt.Errorf("invalid I/O file name %q", name)
		}
	}
	directoryFD, err := unix.Open(
		directoryPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0,
	)
	if err != nil {
		return nil, err
	}
	directory := os.NewFile(uintptr(directoryFD), directoryPath)
	result := &pinnedProcessIO{directory: directory}
	files := make([]*os.File, 0, len(names))
	identities := make([]unix.Stat_t, 0, len(names))
	createdClaims := 0
	completed := false
	defer func() {
		if completed {
			return
		}
		for index := 0; index < createdClaims; index++ {
			removeClaimIfMatching(directoryFD, ioClaimName(claim, index), identities[index])
		}
		for _, file := range files {
			file.Close()
		}
		directory.Close()
	}()

	for index, name := range names {
		flags := unix.O_RDONLY
		if index < 2 {
			flags = unix.O_WRONLY | unix.O_APPEND
		}
		descriptor, openErr := unix.Openat(
			directoryFD, name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0,
		)
		if openErr != nil {
			return nil, openErr
		}
		file := os.NewFile(uintptr(descriptor), name)
		var identity unix.Stat_t
		if statErr := unix.Fstat(descriptor, &identity); statErr != nil {
			file.Close()
			return nil, statErr
		}
		if identity.Mode&unix.S_IFMT != unix.S_IFREG {
			file.Close()
			return nil, fmt.Errorf("I/O file %s is not regular", name)
		}
		files = append(files, file)
		identities = append(identities, identity)
		if linkErr := unix.Linkat(
			descriptor, "", directoryFD, ioClaimName(claim, index), unix.AT_EMPTY_PATH,
		); linkErr != nil {
			return nil, fmt.Errorf("claim I/O file %s: %w", name, linkErr)
		}
		createdClaims++
	}
	for index, name := range names {
		if err := requireNamedIdentity(directoryFD, name, identities[index]); err != nil {
			return nil, fmt.Errorf("I/O file %s changed while being claimed: %w", name, err)
		}
	}
	result.stdout = files[0]
	result.stderr = files[1]
	result.stdin = files[2]
	result.stdinClosed = files[3]
	completed = true
	return result, nil
}

func (processIO *pinnedProcessIO) close() {
	for _, file := range []*os.File{
		processIO.stdout, processIO.stderr, processIO.stdin, processIO.stdinClosed,
	} {
		if file != nil {
			_ = file.Close()
		}
	}
	if processIO.directory != nil {
		_ = processIO.directory.Close()
	}
}

func ioClaimName(claim string, index int) string {
	return fmt.Sprintf(".cengine-io-claim-%s-%d", claim, index)
}

func validIOClaim(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func requireNamedIdentity(parent int, name string, expected unix.Stat_t) error {
	var current unix.Stat_t
	if err := unix.Fstatat(parent, name, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if current.Mode&unix.S_IFMT != unix.S_IFREG ||
		current.Dev != expected.Dev || current.Ino != expected.Ino {
		return errors.New("I/O file identity changed")
	}
	return nil
}

func removeClaimIfMatching(parent int, name string, expected unix.Stat_t) {
	var current unix.Stat_t
	if err := unix.Fstatat(parent, name, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return
	}
	if current.Mode&unix.S_IFMT == unix.S_IFREG &&
		current.Dev == expected.Dev && current.Ino == expected.Ino {
		_ = unix.Unlinkat(parent, name, 0)
	}
}

func duplicateFile(file *os.File, name string) (*os.File, error) {
	descriptor, err := unix.FcntlInt(file.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(descriptor), name), nil
}

func pumpInputStep(source, closed *os.File, destination io.Writer) (bool, error) {
	if _, err := io.Copy(destination, source); err != nil {
		return false, err
	}
	var status unix.Stat_t
	if err := unix.Fstat(int(closed.Fd()), &status); err != nil {
		return false, err
	}
	if status.Mode&unix.S_IFMT != unix.S_IFREG {
		return false, syscall.EINVAL
	}
	return status.Size > 0, nil
}
