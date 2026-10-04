// Package storagepki is a disabled, in-memory TLS credential building block.
// It does not grant storage authority or own the privileged bootstrap signer.
package storagepki

import (
	"crypto/rand"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

var ErrInvalid = errors.New("storagepki: invalid credential or binding")

const ServerName = "storage.cengine.invalid"

type StoreID string
type ServiceEpoch string
type ControllerEpoch uint64
type AttachmentID string
type VolumeID string
type LaunchID string
type PrepareID string
type ContainerID string

type Role string

const (
	ServerRole     Role = "server"
	ControllerRole Role = "controller"
	PrepareRole    Role = "prepare"
	RuntimeRole    Role = "runtime"
)

type Mode string

const (
	ReadOnly  Mode = "read-only"
	ReadWrite Mode = "read-write"
)

// NewUUID always draws a fresh UUIDv4. Convert it to the required semantic ID.
func NewUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&15 | 64
	b[8] = b[8]&63 | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}
func uuid(s string) bool {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' || s[14] != '4' || !strings.ContainsRune("89ab", rune(s[19])) {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}
func container(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}

// AttachmentTuple is copied at construction; it is metadata, not authorization.
type AttachmentTuple struct {
	Attachment AttachmentID
	Volume     VolumeID
	Role       Role
	Mode       Mode
	Container  ContainerID
	Launch     LaunchID
	Prepare    PrepareID
}

// Binding is a frozen, comparable, validated URI SAN value. Its zero value fails.
type Binding struct {
	uri  string
	role Role
}

func (b Binding) URI() string { return b.uri }
func (b Binding) Role() Role  { return b.role }
func NewServerBinding(s StoreID, e ServiceEpoch) (Binding, error) {
	if !uuid(string(s)) || !uuid(string(e)) {
		return Binding{}, ErrInvalid
	}
	return Binding{"spiffe://cengine.storage/store/" + string(s) + "/server/" + string(e), ServerRole}, nil
}

// The epoch must come independently from bootstrap/registry, never from a cert.
func NewControllerBinding(s StoreID, e ControllerEpoch) (Binding, error) {
	if !uuid(string(s)) || e == 0 {
		return Binding{}, ErrInvalid
	}
	return Binding{"spiffe://cengine.storage/store/" + string(s) + "/controller/" + strconv.FormatUint(uint64(e), 10), ControllerRole}, nil
}
func NewAttachmentBinding(s StoreID, e ServiceEpoch, a AttachmentTuple) (Binding, error) {
	if !uuid(string(s)) || !uuid(string(e)) || !uuid(string(a.Attachment)) || !uuid(string(a.Volume)) || !uuid(string(a.Launch)) || !container(string(a.Container)) || (a.Mode != ReadOnly && a.Mode != ReadWrite) {
		return Binding{}, ErrInvalid
	}
	p := "-"
	switch a.Role {
	case PrepareRole:
		if !uuid(string(a.Prepare)) {
			return Binding{}, ErrInvalid
		}
		p = string(a.Prepare)
	case RuntimeRole:
		if a.Prepare != "" {
			return Binding{}, ErrInvalid
		}
	default:
		return Binding{}, ErrInvalid
	}
	return Binding{"spiffe://cengine.storage/store/" + string(s) + "/attachment/" + string(a.Attachment) + "/service/" + string(e) + "/volume/" + string(a.Volume) + "/role/" + string(a.Role) + "/mode/" + string(a.Mode) + "/container/" + string(a.Container) + "/launch/" + string(a.Launch) + "/prepare/" + p, a.Role}, nil
}
