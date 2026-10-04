package consumercompat

import a "dev.cengine/guest/internal/storageauthority"

const (
	WrongVolume = "issued-identity-wrong-volume"
	WrongKey    = "issued-identity-wrong-key"
	WrongRole   = "issued-identity-wrong-role"
	WrongMode   = "issued-identity-wrong-mode"
	WrongEpoch  = "issued-identity-wrong-epoch"
)

func WrongHelloCase(name string) bool {
	switch name {
	case WrongVolume, WrongKey, WrongRole, WrongMode, WrongEpoch:
		return true
	}
	return false
}

// WrongHelloMatches accepts exactly one finite mutation, not an arbitrary tuple.
func WrongHelloMatches(name string, original Original, h a.DataHello) bool {
	b := original.Binding
	want := a.DataHello{Epoch: a.ID(original.Epoch), Binding: a.Binding{Store: a.ID(b.Store), Volume: a.ID(b.Volume), Attachment: a.ID(b.Attachment), Container: a.ContainerID(b.Container), Launch: a.ID(b.Launch), Key: a.Fingerprint(b.Key), Role: a.Role(b.Role), Mode: a.Mode(b.Mode)}}
	switch name {
	case WrongVolume:
		if !ID(string(h.Binding.Volume)) || h.Binding.Volume == want.Binding.Volume {
			return false
		}
		h.Binding.Volume = want.Binding.Volume
	case WrongKey:
		if !Hash(string(h.Binding.Key)) || h.Binding.Key == want.Binding.Key {
			return false
		}
		h.Binding.Key = want.Binding.Key
	case WrongRole:
		if h.Binding.Role != a.PrepareRole || !ID(string(h.Binding.Prepare)) {
			return false
		}
		h.Binding.Role, h.Binding.Prepare = want.Binding.Role, ""
	case WrongMode:
		if want.Binding.Mode != a.ReadOnly || h.Binding.Mode != a.ReadWrite {
			return false
		}
		h.Binding.Mode = want.Binding.Mode
	case WrongEpoch:
		if !ID(string(h.Epoch)) || h.Epoch == want.Epoch {
			return false
		}
		h.Epoch = want.Epoch
	default:
		return false
	}
	return h == want
}
