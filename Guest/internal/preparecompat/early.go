package preparecompat

const EarlyProfile = "rtm096-early-a1-a3-v2"

// DTO validation is independent of build capability. Closed v1 remains closed.
func validArmProfile(a Arm) bool {
	if a.Version == 1 && a.Profile == Profile {
		return a.CaseName == "normal" || a.CaseName == "first-child-published"
	}
	if a.Version == 3 && a.Profile == FullProfile {
		return fullCase(a.CaseName)
	}
	if a.Version != 2 || a.Profile != EarlyProfile {
		return false
	}
	switch a.CaseName {
	case "normal", "before-prepare-send", "guest-accepted-before-prepare", "data-partial-frame":
		return true
	}
	return false
}
func validPhysicalProfile(version uint32, profile string) bool {
	return version == 1 && profile == Profile || version == 2 && profile == EarlyProfile || version == 3 && profile == FullProfile
}
func CurrentProfile() string {
	count := 0
	for _, enabled := range []bool{Enabled(), EarlyEnabled(), FullEnabled()} {
		if enabled {
			count++
		}
	}
	if count != 1 {
		return ""
	}
	if FullEnabled() {
		return FullProfile
	}
	if EarlyEnabled() {
		return EarlyProfile
	}
	if Enabled() {
		return Profile
	}
	return ""
}
func SupportsArm(a Arm) bool { return a.Profile == CurrentProfile() && ValidateArm(a) == nil }

type EarlyObservation struct {
	Version                 uint32 `json:"version"`
	Profile                 string `json:"profile"`
	RequestID               string `json:"requestID"`
	ArmDigest               string `json:"armDigest"`
	Stage                   string `json:"stage"`
	Count                   uint32 `json:"count"`
	TargetAttachment        string `json:"targetAttachment"`
	RequestSequence         uint64 `json:"requestSequence"`
	PrepareCommandsSent     uint32 `json:"prepareCommandsSent"`
	PrepareCommandsAccepted uint32 `json:"prepareCommandsAccepted"`
	DataBytesWritten        uint32 `json:"dataBytesWritten"`
}

func ValidateEarlyObservation(o EarlyObservation) error {
	if !(o.Version == 2 && o.Profile == EarlyProfile || o.Version == 3 && o.Profile == FullProfile) || !id(o.RequestID) || !pin(o.ArmDigest) || o.Count != 1 || !id(o.TargetAttachment) || o.RequestSequence == 0 {
		return ErrInvalidFrame
	}
	var sent, accepted, written uint32
	switch o.Stage {
	case "before-prepare-send":
	case "guest-accepted-before-prepare":
		sent, accepted = 1, 1
	case "data-partial-frame":
		sent, accepted, written = 1, 1, 5
	default:
		return ErrInvalidFrame
	}
	if o.PrepareCommandsSent != sent || o.PrepareCommandsAccepted != accepted || o.DataBytesWritten != written {
		return ErrInvalidFrame
	}
	return nil
}
func DecodeEarlyObservation(raw []byte) (EarlyObservation, error) {
	var o EarlyObservation
	if decode(raw, &o, MaximumObservationBytes) != nil || ValidateEarlyObservation(o) != nil {
		return EarlyObservation{}, ErrInvalidFrame
	}
	return o, nil
}
