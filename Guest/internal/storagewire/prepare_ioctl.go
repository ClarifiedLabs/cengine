package storagewire

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
)

const (
	PrepareIoctlSize           = 8192
	PrepareIoctlVersion uint32 = 1
	// Linux arm64/amd64 _IOWR(0xce, 0x41, byte[8192]). No native Go layout.
	PrepareIoctl        uint32 = 3<<30 | PrepareIoctlSize<<16 | 0xce<<8 | 0x41
	prepareIoctlHeader         = 16
	prepareIoctlRequest uint32 = 1
	prepareIoctlReply   uint32 = 2
)

// The fixed little-endian header is version, operation (request/reply), JSON
// length, reserved-zero. All bytes beyond the JSON payload must also be zero.
func encodePrepareIoctl(op uint32, value any) ([]byte, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if len(payload) == 0 || len(payload) > PrepareIoctlSize-prepareIoctlHeader {
		return nil, invalid("prepare ioctl payload size")
	}
	out := make([]byte, PrepareIoctlSize)
	binary.LittleEndian.PutUint32(out, PrepareIoctlVersion)
	binary.LittleEndian.PutUint32(out[4:], op)
	binary.LittleEndian.PutUint32(out[8:], uint32(len(payload)))
	copy(out[prepareIoctlHeader:], payload)
	return out, nil
}
func decodePrepareIoctl(buf []byte, op uint32, value any) error {
	if len(buf) != PrepareIoctlSize || binary.LittleEndian.Uint32(buf) != PrepareIoctlVersion || binary.LittleEndian.Uint32(buf[4:]) != op || binary.LittleEndian.Uint32(buf[12:]) != 0 {
		return invalid("prepare ioctl header")
	}
	n := binary.LittleEndian.Uint32(buf[8:])
	if n == 0 || n > PrepareIoctlSize-prepareIoctlHeader {
		return invalid("prepare ioctl payload size")
	}
	tail := buf[prepareIoctlHeader+int(n):]
	if !bytes.Equal(tail, make([]byte, len(tail))) {
		return invalid("prepare ioctl nonzero tail")
	}
	return strictDecode(buf[prepareIoctlHeader:prepareIoctlHeader+int(n)], value)
}

// Node/Handle MUST be zero at the userspace ioctl boundary. The adapter supplies
// both exclusively from the kernel header and this mount's actual local grant.
func EncodePrepareIoctl(r PrepareRequest) ([]byte, error) {
	if r.Node != 0 || r.Handle != 0 {
		return nil, invalid("prepare ioctl supplied routing")
	}
	if err := validatePrepareRequest(r); err != nil {
		return nil, err
	}
	out, err := encodePrepareIoctl(prepareIoctlRequest, r)
	if err != nil {
		return nil, err
	}
	_, err = DecodePrepareIoctl(out)
	return out, err
}
func DecodePrepareIoctl(buf []byte) (PrepareRequest, error) {
	var r PrepareRequest
	if err := decodePrepareIoctl(buf, prepareIoctlRequest, &r); err != nil {
		return PrepareRequest{}, err
	}
	if r.Node != 0 || r.Handle != 0 {
		return PrepareRequest{}, invalid("prepare ioctl supplied routing")
	}
	if err := validatePrepareRequest(r); err != nil {
		return PrepareRequest{}, err
	}
	return r, nil
}
func EncodePrepareIoctlReply(r PrepareReply) ([]byte, error) {
	if err := validatePrepareReply(r); err != nil {
		return nil, err
	}
	out, err := encodePrepareIoctl(prepareIoctlReply, r)
	if err != nil {
		return nil, err
	}
	_, err = DecodePrepareIoctlReply(out)
	return out, err
}
func DecodePrepareIoctlReply(buf []byte) (PrepareReply, error) {
	var r PrepareReply
	if err := decodePrepareIoctl(buf, prepareIoctlReply, &r); err != nil {
		return PrepareReply{}, err
	}
	if err := validatePrepareReply(r); err != nil {
		return PrepareReply{}, err
	}
	return r, nil
}
