//go:build darwin

package storageauthority

import (
	"os"

	"golang.org/x/sys/unix"
)

func renameCopyNoReplace(from *os.File, name string, to *os.File, target string) error {
	return unix.RenameatxNp(int(from.Fd()), name, int(to.Fd()), target, unix.RENAME_EXCL)
}

func copyInitialMetadata(st *unix.Stat_t) CopyCleanupV1 {
	return CopyCleanupV1{UID: st.Uid, GID: st.Gid, Mode: uint32(st.Mode) & 07777, ATimeSeconds: st.Atim.Sec, MTimeSeconds: st.Mtim.Sec, ATimeNanos: uint32(st.Atim.Nsec), MTimeNanos: uint32(st.Mtim.Nsec)}
}
