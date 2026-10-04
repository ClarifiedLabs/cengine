// Package preparecompat is the closed, non-authorizing RTM096 carrier vocabulary.
package preparecompat

type BootBinding struct {
	ShimLaunchUUID string `json:"shimLaunchUUID"`
	GuestBootNonce string `json:"guestBootNonce"`
}

type Scope struct {
	Intent              string `json:"intent"`
	Store               string `json:"store"`
	ServiceEpoch        string `json:"serviceEpoch"`
	ControllerEpoch     uint64 `json:"controllerEpoch"`
	ControllerKey       string `json:"controllerKey"`
	Container           string `json:"container"`
	ContainerInstance   string `json:"containerInstance"`
	Launch              string `json:"launch"`
	Prepare             string `json:"prepare"`
	SpecificationDigest string `json:"specificationDigest"`
}

type Slot struct {
	Volume     string `json:"volume"`
	Attachment string `json:"attachment"`
	Role       string `json:"role"`
	Mode       string `json:"mode"`
}

type MountBinding struct {
	Index       uint32 `json:"index"`
	Volume      string `json:"volume"`
	Destination string `json:"destination"`
	Subpath     string `json:"subpath"`
	Mode        string `json:"mode"`
	NoCopy      bool   `json:"noCopy"`
}

const Profile = "rtm096-normal-a7-v1"
const MaximumArmBytes = 64 << 10
const MaximumObservationBytes = 8 << 10

type Credential struct {
	Attachment        string `json:"attachment"`
	Key               string `json:"key"`
	CertificateSHA256 string `json:"certificateSHA256"`
}
type Arm struct {
	Version          uint32         `json:"version"`
	Profile          string         `json:"profile"`
	RequestID        string         `json:"requestID"`
	CaseName         string         `json:"caseName"`
	TargetAttachment string         `json:"targetAttachment"`
	Binding          BootBinding    `json:"binding"`
	Scope            Scope          `json:"scope"`
	Mounts           []MountBinding `json:"mounts"`
	Slots            []Slot         `json:"slots"`
	Credentials      []Credential   `json:"credentials"`
}
type ObjectIdentity struct {
	Inode      uint64 `json:"inode"`
	Generation uint32 `json:"generation"`
	FileType   uint32 `json:"fileType"`
	Handle     string `json:"handle"`
}

// SourceAtimes is PID1's read-only source snapshot, not sealed manifest data.
// Values are unsigned nanoseconds constrained to the signed Int64 range.
type SourceAtimes struct {
	Root uint64 `json:"root"`
	A    uint64 `json:"a"`
	Z    uint64 `json:"z"`
}

func (a SourceAtimes) Valid() bool {
	const max = uint64(1<<63 - 1)
	return a.Root <= max && a.A <= max && a.Z <= max
}

type Observation struct {
	SourceAtimes     SourceAtimes   `json:"sourceAtimes"`
	Version          uint32         `json:"version"`
	Profile          string         `json:"profile"`
	RequestID        string         `json:"requestID"`
	ArmDigest        string         `json:"armDigest"`
	Stage            string         `json:"stage"`
	Count            uint32         `json:"count"`
	TargetAttachment string         `json:"targetAttachment"`
	CopyIntent       string         `json:"copyIntent"`
	FilesystemUUID   string         `json:"filesystemUUID"`
	ManifestDigest   string         `json:"manifestDigest"`
	ManifestSize     uint64         `json:"manifestSize"`
	Root             ObjectIdentity `json:"root"`
	Transaction      ObjectIdentity `json:"transaction"`
	Published        ObjectIdentity `json:"published"`
	Staged           ObjectIdentity `json:"staged"`
}
