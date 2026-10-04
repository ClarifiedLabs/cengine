package storageboot

import (
	"dev.cengine/guest/internal/diskbootstrap"
	a "dev.cengine/guest/internal/storageauthority"
	s "dev.cengine/guest/internal/storageservice"
	"encoding/hex"
	"errors"
	"strings"
)

const (
	Port        = 4106
	ControlPort = 4107
	CSRPort     = 4108
)

var errFrame = errors.New("invalid-frame")

func uuid(s string) bool {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' || strings.ToLower(s) != s || s == "00000000-0000-0000-0000-000000000000" {
		return false
	}
	b, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	return err == nil && len(b) == 16
}

func id(s string) bool { return uuid(s) && s[14] == '4' && strings.ContainsRune("89ab", rune(s[19])) }

func pin(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == s
}

func validBinding(b diskbootstrap.StorageBinding) bool {
	return id(b.ShimLaunchUUID) && id(b.GuestBootNonce) && uuid(b.Ext4UUID) && b.Bytes > 0 && b.Bytes <= 1<<63-1
}

func validNotification(h a.DataHello) bool {
	b := h.Binding
	return id(string(h.Epoch)) && id(string(b.Store)) && id(string(b.Volume)) && id(string(b.Attachment)) && id(string(b.Launch)) && pin(string(b.Container)) && pin(string(b.Key)) && (b.Mode == a.ReadOnly || b.Mode == a.ReadWrite) && (b.Role == a.RuntimeRole && b.Prepare == "" || b.Role == a.PrepareRole && id(string(b.Prepare)))
}

func validIsolationRequest(r *s.IsolationRequest) bool {
	return r != nil && id(r.RequestID) && id(r.OperationUUID) && id(r.Challenge) && pin(r.ArmDigest)
}
