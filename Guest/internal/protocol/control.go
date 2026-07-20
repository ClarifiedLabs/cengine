package protocol

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	Version                         = 9
	ControlPort                     = 4100
	FileSystemPort                  = 4101
	RootFSContentPort               = 4102
	ExecIOPort                      = 4103
	PortProxyPort                   = 4104
	SocketProxyPortBase             = 4200
	MaxControlFrame                 = 16 << 20
	MaxFileSystemIO                 = 4 << 20
	ErrorResourceRollbackIncomplete = "resource_rollback_incomplete"
)

type Envelope struct {
	Version   uint32          `json:"version"`
	ID        string          `json:"id"`
	Operation string          `json:"operation"`
	Payload   json.RawMessage `json:"payload,omitempty"`
	Error     *Error          `json:"error,omitempty"`
}

type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type WorkloadSpec struct {
	ID               string            `json:"id"`
	RootDevice       string            `json:"rootDevice"`
	Arguments        []string          `json:"arguments"`
	Environment      []string          `json:"environment"`
	WorkingDirectory string            `json:"workingDirectory"`
	Hostname         string            `json:"hostname"`
	User             User              `json:"user"`
	Terminal         bool              `json:"terminal"`
	ReadOnlyRoot     bool              `json:"readOnlyRoot"`
	StopSignal       string            `json:"stopSignal"`
	VolumeServer     string            `json:"volumeServer,omitempty"`
	Mounts           []Mount           `json:"mounts"`
	Networks         []NetworkEndpoint `json:"networks"`
	Hosts            map[string]string `json:"hosts,omitempty"`
	Resources        Resources         `json:"resources"`
	Privileged       bool              `json:"privileged"`
	Annotations      map[string]string `json:"annotations,omitempty"`
	CapabilityAdd    []string          `json:"capabilityAdd,omitempty"`
	CapabilityDrop   []string          `json:"capabilityDrop,omitempty"`
	Rlimits          []Rlimit          `json:"rlimits,omitempty"`
	IOClaim          string            `json:"ioClaim"`
}

type User struct {
	UID              uint32   `json:"uid"`
	GID              uint32   `json:"gid"`
	AdditionalGroups []uint32 `json:"additionalGroups,omitempty"`
	Username         string   `json:"username,omitempty"`
}

type Rlimit struct {
	Type string `json:"type"`
	Soft uint64 `json:"soft"`
	Hard uint64 `json:"hard"`
}

type Mount struct {
	Kind        string   `json:"kind"`
	Source      string   `json:"source"`
	Device      string   `json:"device,omitempty"`
	Destination string   `json:"destination"`
	ReadOnly    bool     `json:"readOnly"`
	Options     []string `json:"options,omitempty"`
	Subpath     string   `json:"subpath,omitempty"`
	NoCopy      bool     `json:"noCopy,omitempty"`
	Propagation string   `json:"propagation,omitempty"`
	SocketPort  uint32   `json:"socketPort,omitempty"`
	SocketMode  uint32   `json:"socketMode,omitempty"`
	SocketUID   uint32   `json:"socketUID,omitempty"`
	SocketGID   uint32   `json:"socketGID,omitempty"`
}

type NetworkEndpoint struct {
	NetworkID  string   `json:"networkID"`
	VLAN       uint16   `json:"vlan"`
	Name       string   `json:"name"`
	MACAddress string   `json:"macAddress"`
	Addresses  []string `json:"addresses"`
	Gateways   []string `json:"gateways"`
	DNS        []string `json:"dns"`
	Aliases    []string `json:"aliases"`
	Sysctls    []string `json:"sysctls"`
}

type Resources struct {
	MemoryBytes      uint64            `json:"memoryBytes"`
	CPUQuota         int64             `json:"cpuQuota"`
	CPUPeriod        uint64            `json:"cpuPeriod"`
	PIDs             int64             `json:"pids"`
	BlockIOReadBps   []BlockIOThrottle `json:"blockIOReadBps"`
	BlockIOWriteBps  []BlockIOThrottle `json:"blockIOWriteBps"`
	BlockIOReadIOps  []BlockIOThrottle `json:"blockIOReadIOps"`
	BlockIOWriteIOps []BlockIOThrottle `json:"blockIOWriteIOps"`
}

type BlockIOThrottle struct {
	Path string `json:"path"`
	Rate uint64 `json:"rate"`
}

type ResourceUpdate struct {
	Resources                       Resources `json:"resources"`
	CompatibilityFailureAfterWrites uint32    `json:"compatibilityFailureAfterWrites,omitempty"`
}

type ProcessStatus struct {
	Status   string `json:"status"`
	PID      int    `json:"pid,omitempty"`
	ExitCode *int   `json:"exitCode,omitempty"`
}

type SignalRequest struct {
	Signal int `json:"signal"`
}

type NetworkRequest struct {
	Endpoint NetworkEndpoint `json:"endpoint"`
	Name     string          `json:"name,omitempty"`
}

type ExecSpec struct {
	ID               string   `json:"id"`
	Arguments        []string `json:"arguments"`
	Environment      []string `json:"environment"`
	WorkingDirectory string   `json:"workingDirectory"`
	User             User     `json:"user"`
	Terminal         bool     `json:"terminal"`
	AttachStdin      bool     `json:"attachStdin"`
	AttachStdout     bool     `json:"attachStdout"`
	AttachStderr     bool     `json:"attachStderr"`
	NoNewPrivileges  bool     `json:"noNewPrivileges"`
	Privileged       bool     `json:"privileged"`
	CapabilityAdd    []string `json:"capabilityAdd,omitempty"`
	CapabilityDrop   []string `json:"capabilityDrop,omitempty"`
	Rlimits          []Rlimit `json:"rlimits,omitempty"`
	IOClaim          string   `json:"ioClaim"`
}

type RootFSLayer struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

type RootFSRequest struct {
	RootDevice string        `json:"rootDevice"`
	Layers     []RootFSLayer `json:"layers"`
}

func ReadEnvelope(reader io.Reader) (Envelope, error) {
	var size uint32
	if err := binary.Read(reader, binary.BigEndian, &size); err != nil {
		return Envelope{}, err
	}
	if size == 0 || size > MaxControlFrame {
		return Envelope{}, fmt.Errorf("invalid control frame size %d", size)
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(reader, data); err != nil {
		return Envelope{}, err
	}
	var envelope Envelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return Envelope{}, err
	}
	if envelope.Version != Version {
		return Envelope{}, fmt.Errorf("unsupported protocol version %d", envelope.Version)
	}
	if envelope.ID == "" || envelope.Operation == "" {
		return Envelope{}, errors.New("control envelope requires id and operation")
	}
	return envelope, nil
}

func WriteEnvelope(writer io.Writer, envelope Envelope) error {
	if envelope.Version == 0 {
		envelope.Version = Version
	}
	data, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	if len(data) == 0 || len(data) > MaxControlFrame {
		return fmt.Errorf("invalid control frame size %d", len(data))
	}
	if err := binary.Write(writer, binary.BigEndian, uint32(len(data))); err != nil {
		return err
	}
	for len(data) > 0 {
		count, err := writer.Write(data)
		if err != nil {
			return err
		}
		if count == 0 {
			return io.ErrShortWrite
		}
		data = data[count:]
	}
	return nil
}
