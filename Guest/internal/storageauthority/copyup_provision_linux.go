//go:build linux

package storageauthority

import (
	"os"

	"golang.org/x/sys/unix"
)

func renameCopyNoReplace(from *os.File, name string, to *os.File, target string) error {
	return unix.Renameat2(int(from.Fd()), name, int(to.Fd()), target, unix.RENAME_NOREPLACE)
}

func copyInitialMetadata(st *unix.Stat_t) CopyCleanupV1 {
	return CopyCleanupV1{UID: st.Uid, GID: st.Gid, Mode: st.Mode & 07777, ATimeSeconds: st.Atim.Sec, MTimeSeconds: st.Mtim.Sec, ATimeNanos: uint32(st.Atim.Nsec), MTimeNanos: uint32(st.Mtim.Nsec)}
}
