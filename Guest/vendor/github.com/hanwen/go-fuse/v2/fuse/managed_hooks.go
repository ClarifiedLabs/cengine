// CEngine downstream additions; see ../CENGINE-FORK.md.
package fuse

import (
	"io"
)

// ReplyDelivery is an immutable observation of one native device response.
// Status is the filesystem result; Err is transport failure (including a short
// write), not the filesystem errno. Suppressed includes normal no-reply opcodes;
// consumers distinguish those by Opcode. Interrupted includes canceled requests.
// No pointer to request memory, descriptor, or response method escapes.
type ReplyDelivery struct {
	Unique                  uint64
	Opcode                  uint32
	Status                  Status
	Bytes, Expected         int
	Suppressed, Interrupted bool
	Err                     error
}

func validateInit(check func(InitOut) error, out InitOut) (ok bool) {
	if check == nil {
		return true
	}
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	return check(out) == nil
}

func deliverObserved(req *request, interrupted bool, write func([][]byte) (int, error), observer func(ReplyDelivery)) (status Status) {
	h := req.inHeader()
	result := ReplyDelivery{Unique: h.Unique, Opcode: h.Opcode, Status: req.status, Suppressed: req.suppressReply, Interrupted: interrupted}
	if !req.suppressReply {
		iov := [][]byte{req.outHeaderBuf, req.outDataBuf, req.outPayload}
		result.Expected = iovLen(iov)
		result.Bytes, result.Err = write(iov)
		if result.Err == nil && result.Bytes != result.Expected {
			result.Err = io.ErrShortWrite
		}
	}
	if result.Err == io.ErrShortWrite {
		status = EIO
	} else {
		status = ToStatus(result.Err)
	}
	// The response has already been attempted. A panicking observer must not make
	// a caller infer success, retry the response, or escape into a serving goroutine.
	defer func() {
		if recover() != nil {
			status = EIO
		}
	}()
	observer(result)
	return status
}
