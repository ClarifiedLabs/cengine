//go:build cengine_native_faulttest && linux && (arm64 || amd64)

package storageservice

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"net"
	"strings"
	"unsafe"

	a "dev.cengine/guest/internal/storageauthority"
	p "dev.cengine/guest/internal/storagepki"
	d "dev.cengine/guest/internal/storageserver"
	"golang.org/x/sys/unix"
)

// NativePendingProvision is a single test-binary-only lower-authority crash setup,
// not a DATA dispatcher or production activation API. It authenticates an issued
// current-E RW PREPARE identity and retains a REAL admitted guard and provision
// obligation. Success must be followed by the fixture's joined process crash;
// it cannot return a principal/guard, discharge the marker, or fake retirement.
func (s *commonService) NativePendingProvision(ctx context.Context, raw net.Conn, hello a.DataHello) (a.CopyIntent, error) {
	if ctx == nil || raw == nil || hello.Binding.Role != a.PrepareRole || hello.Binding.Mode != a.ReadWrite {
		return a.CopyIntent{}, a.ErrUnauthorized
	}
	done, err := s.begin(raw, false)
	if err != nil {
		return a.CopyIntent{}, err
	}
	defer done()
	defer raw.Close()
	meta, err := s.authority.StartupMetadata()
	if err != nil {
		return a.CopyIntent{}, err
	}
	if hello.Epoch != meta.Epoch || hello.Binding.Store != meta.Store.ID {
		return a.CopyIntent{}, a.ErrUnauthorized
	}
	cfg, err := p.ServerTLSConfig(s.identity, s.issuer.Root())
	if err != nil {
		return a.CopyIntent{}, err
	}
	conn := tls.Server(raw, cfg)
	if err = conn.HandshakeContext(ctx); err != nil {
		return a.CopyIntent{}, err
	}
	binding, err := d.AttachmentBinding(hello)
	if err != nil {
		return a.CopyIntent{}, err
	}
	key, err := pin(hello.Binding.Key)
	if err != nil {
		return a.CopyIntent{}, err
	}
	if err = p.VerifyAttachment(conn.ConnectionState(), s.issuer.Root(), binding, key); err != nil {
		return a.CopyIntent{}, err
	}
	principal, err := s.authority.AuthenticateData(ctx, conn, hello)
	if err != nil {
		return a.CopyIntent{}, err
	}
	guard, err := s.authority.Admit(principal, hello.Binding.Volume, true)
	if err != nil {
		return a.CopyIntent{}, err
	}
	retained := false
	defer func() {
		if !retained {
			guard.Release()
		}
	}()
	root, err := guard.DupVolumeRoot()
	if err != nil {
		return a.CopyIntent{}, err
	}
	defer root.Close()
	object, err := nativePendingObject(int(root.Fd()))
	if err != nil {
		return a.CopyIntent{}, err
	}
	device, err := guard.CopyDeviceID()
	if err != nil {
		return a.CopyIntent{}, err
	}
	expected, err := hex.DecodeString(strings.ReplaceAll(device, "-", ""))
	if err != nil || len(expected) != 16 {
		return a.CopyIntent{}, a.ErrInvalid
	}
	var fsuuid [17]byte
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, root.Fd(), 0x80111500, uintptr(unsafe.Pointer(&fsuuid[0])))
	if errno != 0 {
		return a.CopyIntent{}, errno
	}
	var uuid [16]byte
	copy(uuid[:], fsuuid[1:])
	if fsuuid[0] != 16 || uuid == ([16]byte{}) || string(uuid[:]) != string(expected) {
		return a.CopyIntent{}, unix.EXDEV
	}
	op, err := guard.BeginCopyOperation(1, a.CopyOperationBegin, "")
	if err != nil {
		return a.CopyIntent{}, err
	}
	intent, err := guard.BeginCopy(a.CopyRootV1{Store: hello.Binding.Store, Volume: hello.Binding.Volume, BackingUUID: uuid, Root: object})
	if err != nil {
		return a.CopyIntent{}, err
	}
	if err = op.Complete(nil); err != nil {
		return a.CopyIntent{}, err
	}
	if _, err = guard.BeginCopyOperation(2, a.CopyOperationProvision, intent.ID); err != nil {
		return a.CopyIntent{}, err
	}
	intent, err = guard.ProvisionCopyTransaction(intent.ID, nativePendingObject)
	if err != nil {
		return a.CopyIntent{}, err
	}
	retained = true
	return intent, nil
}

// Actual ext4 FILEID_INO32_GEN from the guard-derived retained root/private FD.
func nativePendingObject(fd int) (a.Ext4ObjectV1, error) {
	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err != nil {
		return a.Ext4ObjectV1{}, err
	}
	if fs.Type != unix.EXT4_SUPER_MAGIC {
		return a.Ext4ObjectV1{}, unix.EXDEV
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return a.Ext4ObjectV1{}, err
	}
	handle, _, err := unix.NameToHandleAt(fd, "", unix.AT_EMPTY_PATH)
	if err != nil {
		return a.Ext4ObjectV1{}, err
	}
	b := handle.Bytes()
	if handle.Type() != 1 || len(b) != 8 || st.Ino == 0 || uint64(binary.LittleEndian.Uint32(b)) != st.Ino || st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return a.Ext4ObjectV1{}, unix.EOPNOTSUPP
	}
	object := a.Ext4ObjectV1{Inode: st.Ino, Generation: binary.LittleEndian.Uint32(b[4:]), FileType: unix.S_IFDIR, HandleType: 1, HandleSize: 8}
	copy(object.Handle[:], b)
	return object, nil
}

func (s *LifecycleService) NativePendingProvision(ctx context.Context, raw net.Conn, hello a.DataHello) (a.CopyIntent, error) {
	if !s.valid() {
		if raw != nil {
			_ = raw.Close()
		}
		return a.CopyIntent{}, ErrConfiguration
	}
	return s.owner.NativePendingProvision(ctx, raw, hello)
}
