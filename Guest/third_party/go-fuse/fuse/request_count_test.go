package fuse

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"syscall"
	"testing"
	"time"
)

// Exercise the actual native read/pool path without mounting a filesystem. A
// datagram pair preserves /dev/fuse's one-request-per-read shape. Single-reader
// mode keeps reads under test control; callback completion uses returnRequest.
func countReader(t *testing.T, count, bytes int) (*fuseFD, int) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Close(fds[1]) })
	opts := &MountOptions{MaxWrite: 128 << 10, MaxInflightRequests: count, MaxInflightRequestBytes: bytes, Logger: log.New(io.Discard, "", 0)}
	opts.setDefaults(NewDefaultRawFileSystem())
	srv := &Server{opts: opts, maxReaders: 2, singleReader: true}
	srv.reqPool.New = func() any { return &requestAlloc{request: request{cancel: make(chan struct{})}} }
	_, size, _ := requestAccountingSizes(opts.MaxWrite)
	srv.readPool.New = func() any { return make([]byte, size) }
	r, err := srv.newFuseFD(fds[0])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.close() })
	return r, fds[1]
}

func sendCountRequest(t *testing.T, fd int, opcode uint32, unique uint64, size int) {
	t.Helper()
	data := make([]byte, size)
	binary.LittleEndian.PutUint32(data[0:4], uint32(size))
	binary.LittleEndian.PutUint32(data[4:8], opcode)
	binary.LittleEndian.PutUint64(data[8:16], unique)
	if n, err := syscall.Write(fd, data); err != nil || n != len(data) {
		t.Fatalf("send: %d %v", n, err)
	}
}

func TestInflightRequestCountRetainsSmallRequestsUntilCompletion(t *testing.T) {
	for _, opcode := range []uint32{_OP_GETATTR, _OP_RELEASE, _OP_RELEASEDIR, _OP_FORGET, _OP_BATCH_FORGET} {
		t.Run(operationName(opcode), func(t *testing.T) {
			const limit = 16
			r, peer := countReader(t, limit, limit*((128<<10)+4096))
			var held []*requestAlloc
			defer func() {
				for _, req := range held {
					r.returnRequest(req)
				}
			}()
			for i := 0; i < limit; i++ {
				sendCountRequest(t, peer, opcode, uint64(i+1), 64)
				req, code := r.readRequest()
				if req == nil || code != OK {
					t.Fatalf("read %d: %p %v", i, req, code)
				}
				held = append(held, req)
				if req.bufferPoolInputBuf != nil || r.inflightRequestBytes != len(held)*r.reqAllocBytes {
					t.Fatal("small input did not release its large buffer")
				}
			}
			// The byte budget has plenty of room, but all callback slots are owned.
			// The next PREPARE-shaped IOCTL must remain unread, not fail a mount.
			sendCountRequest(t, peer, _OP_IOCTL, 99, 192)
			if req, code := r.readRequest(); req != nil || code != OK {
				if req != nil {
					r.returnRequest(req)
				}
				t.Fatalf("overflow entered native dispatch: %p %v", req, code)
			}
			r.returnRequest(held[0])
			held = held[1:]
			req, code := r.readRequest()
			if req == nil || code != OK {
				t.Fatalf("reader did not resume: %p %v", req, code)
			}
			held = append(held, req)
			if req.inHeader().Unique != 99 || req.inHeader().Opcode != _OP_IOCTL {
				t.Fatal("queued IOCTL lost or replaced")
			}
		})
	}
}

func TestInflightRequestCountDefaultsAndByteBudget(t *testing.T) {
	for _, count := range []int{-1, 0, 1, 2} {
		r, peer := countReader(t, count, 0)
		sendCountRequest(t, peer, _OP_GETATTR, 1, 64)
		a, code := r.readRequest()
		if a == nil || code != OK {
			t.Fatal("first read failed")
		}
		sendCountRequest(t, peer, _OP_GETATTR, 2, 64)
		b, code := r.readRequest()
		if code != OK || (b == nil) != (count == 1) {
			t.Fatalf("count %d: second read %p %v", count, b, code)
		}
		r.returnRequest(a)
		if b == nil {
			b, code = r.readRequest()
		}
		if b == nil || code != OK || b.inHeader().Unique != 2 {
			t.Fatal("count-one reader did not resume")
		}
		r.returnRequest(b)
		if r.inflightRequests != 0 || r.inflightRequestBytes != 0 || r.reqReaders != 0 {
			t.Fatal("leaked request accounting")
		}
	}
	// The existing one-request byte-budget exemption must not bypass a full
	// count budget; conversely a high count must not bypass the byte budget.
	r, peer := countReader(t, 16, 1)
	sendCountRequest(t, peer, _OP_IOCTL, 1, 192)
	a, code := r.readRequest()
	if a == nil || code != OK {
		t.Fatal("one-request byte exemption removed")
	}
	sendCountRequest(t, peer, _OP_GETATTR, 2, 64)
	if b, code := r.readRequest(); b != nil || code != OK {
		t.Fatal("count bypassed byte budget")
	}
	r.returnRequest(a)
	b, code := r.readRequest()
	if b == nil || code != OK || b.inHeader().Unique != 2 {
		t.Fatal("byte-budget reader did not resume")
	}
	r.returnRequest(b)
}

type countBlockingFS struct {
	defaultRawFileSystem
	entered  chan uint64
	releases []chan struct{}
	stop     chan struct{}
}

func (f *countBlockingFS) GetAttr(_ <-chan struct{}, in *GetAttrIn, out *AttrOut) Status {
	f.entered <- in.Unique
	select {
	case <-f.releases[in.Unique-1]:
	case <-f.stop:
	}
	out.Attr = Attr{Ino: in.NodeId, Mode: S_IFREG | 0600, Nlink: 1}
	return OK
}

// Drive Serve itself, not a manually replenished reader. At saturation the
// cap-reaching callback stays inline in a live loop (both reader strategies).
// Its completion must allow the queued request and exact reply to progress.
func TestInflightRequestCountServeResumesAtSaturation(t *testing.T) {
	for _, single := range []bool{false, true} {
		for _, limit := range []int{1, 16} {
			t.Run(fmt.Sprintf("single=%t/limit=%d", single, limit), func(t *testing.T) {
				r, peer := countReader(t, limit, 0)
				fs := &countBlockingFS{entered: make(chan uint64, limit+1), releases: make([]chan struct{}, limit+1), stop: make(chan struct{})}
				for i := range fs.releases {
					fs.releases[i] = make(chan struct{})
				}
				srv := r.server
				srv.protocolServer = NewProtocolServer(fs, srv.opts).protocolServer
				srv.kernelSettings = InitIn{Major: 7, Minor: 33}
				srv.singleReader, srv.fuseFD = single, r
				srv.fuseFD.loops.Add(1)
				done := make(chan struct{})
				t.Cleanup(func() {
					close(fs.stop)
					_ = r.withFD(func(fd int) { _ = syscall.Shutdown(fd, syscall.SHUT_RDWR) })
					select {
					case <-done:
					case <-time.After(5 * time.Second):
						t.Error("Serve did not join")
					}
				})
				go func() { srv.Serve(); close(done) }()
				for i := 0; i <= limit; i++ {
					sendCountRequest(t, peer, _OP_GETATTR, uint64(i+1), 64)
				}
				for i := 0; i < limit; i++ {
					select {
					case <-fs.entered:
					case <-done:
						t.Fatal("Serve exited while callbacks were owned")
					case <-time.After(5 * time.Second):
						t.Fatal("callback did not enter")
					}
				}
				select {
				case id := <-fs.entered:
					t.Fatalf("overflow callback %d admitted", id)
				case <-done:
					t.Fatal("Serve exited at saturation")
				case <-time.After(20 * time.Millisecond):
				}
				// The last admitted callback is the single-reader inline owner.
				close(fs.releases[limit-1])
				select {
				case id := <-fs.entered:
					if id != uint64(limit+1) {
						t.Fatalf("unexpected queued callback %d", id)
					}
				case <-done:
					t.Fatal("Serve exited instead of resuming")
				case <-time.After(5 * time.Second):
					t.Fatal("queued callback did not resume")
				}
				for i := range fs.releases {
					if i != limit-1 {
						close(fs.releases[i])
					}
				}
				if err := syscall.SetsockoptTimeval(peer, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 5}); err != nil {
					t.Fatal(err)
				}
				seen := make(map[uint64]bool)
				for i := 0; i <= limit; i++ {
					data := make([]byte, 1024)
					n, err := syscall.Read(peer, data)
					if err != nil || n < 16 || binary.LittleEndian.Uint32(data[4:8]) != 0 {
						t.Fatalf("reply %d: %d %v", i, n, err)
					}
					id := binary.LittleEndian.Uint64(data[8:16])
					if id == 0 || id > uint64(limit+1) || seen[id] {
						t.Fatalf("duplicate/foreign reply %d", id)
					}
					seen[id] = true
				}
				select {
				case <-done:
					t.Fatal("Serve lost its reader after completion")
				default:
				}
			})
		}
	}
}

func TestInflightRequestCountReturnedOnReadFailure(t *testing.T) {
	for _, short := range []bool{false, true} {
		r, peer := countReader(t, 1, 0)
		if short {
			if _, err := syscall.Write(peer, []byte{1}); err != nil {
				t.Fatal(err)
			}
		} else {
			if err := r.close(); err != nil {
				t.Fatal(err)
			}
		}
		if req, code := r.readRequest(); req != nil || code == OK {
			t.Fatal("bad read accepted")
		}
		if r.inflightRequests != 0 || r.inflightRequestBytes != 0 || r.reqReaders != 0 || !r.canAcceptAnother() {
			t.Fatal("failed read leaked admission")
		}
	}
}
