package nfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"

	"github.com/willscott/go-nfs-client/nfs/rpc"
)

// Identity is the AUTH_SYS identity asserted by a trusted client, not a
// cryptographically authenticated principal. Groups contains at most 16 gids.
type Identity struct {
	UID, GID uint32
	Groups   []uint32
}

// RequestIdentityHandler opts into mandatory AUTH_SYS for non-NULL RPCs.
// The callback is synchronous and must not start goroutines or retain open
// files. Implementations must isolate credentials from concurrent requests.
type RequestIdentityHandler interface {
	WithIdentity(context.Context, Identity, func() error) error
}

// ParseAuthSys validates RFC 5531 authsys_parms, including XDR bounds and the
// Linux reserved uid/gid sentinel. No identity is inherited from a connection.
func ParseAuthSys(auth rpc.Auth) (Identity, error) {
	var id Identity
	bad := fmt.Errorf("invalid AUTH_SYS credentials")
	if auth.Flavor != 1 || len(auth.Body) > 400 {
		return id, bad
	}
	r := bytes.NewReader(auth.Body)
	word := func() (uint32, error) { var n uint32; err := binary.Read(r, binary.BigEndian, &n); return n, err }
	if _, err := word(); err != nil {
		return id, bad
	}
	n, err := word()
	if err != nil || n > 255 || uint64((n+3)&^3) > uint64(r.Len()) {
		return id, bad
	}
	name := make([]byte, (n+3)&^3)
	if _, err := r.Read(name); err != nil && len(name) != 0 {
		return id, bad
	}
	for _, b := range name[n:] {
		if b != 0 {
			return id, bad
		}
	}
	if id.UID, err = word(); err != nil || id.UID == ^uint32(0) {
		return Identity{}, bad
	}
	if id.GID, err = word(); err != nil || id.GID == ^uint32(0) {
		return Identity{}, bad
	}
	n, err = word()
	if err != nil || n > 16 || r.Len() != int(n)*4 {
		return Identity{}, bad
	}
	id.Groups = make([]uint32, n)
	for i := range id.Groups {
		id.Groups[i], err = word()
		if err != nil || id.Groups[i] == ^uint32(0) {
			return Identity{}, bad
		}
	}
	return id, nil
}

// AccessFilesystem reports the subset of NFS ACCESS bits the current request
// can exercise. Credential-aware exports must implement this with kernel checks.
type AccessFilesystem interface {
	Access(string, uint32) (uint32, error)
}

func validOperationName(name []byte) bool {
	return len(name) > 0 && !bytes.Equal(name, []byte(".")) && !bytes.Equal(name, []byte("..")) && bytes.IndexByte(name, '/') < 0 && bytes.IndexByte(name, 0) < 0
}
