package nfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"syscall"
	"testing"

	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/osfs"
	"github.com/willscott/go-nfs-client/nfs/xdr"
)

type writeTestFS struct {
	billy.Filesystem
	file        *writeTestFile
	unsupported bool
	opens       int
}

func (f *writeTestFS) OpenFile(name string, flags int, mode os.FileMode) (billy.File, error) {
	f.opens++
	if name != "file" || flags != os.O_WRONLY || mode != 0600 {
		f.file.t.Fatalf("unexpected open: %q flags=%d mode=%04o", name, flags, mode)
	}
	file, err := f.Filesystem.OpenFile(name, flags, mode)
	if err != nil {
		return nil, err
	}
	f.file.File = file
	if f.unsupported {
		return f.file, nil
	}
	return &syncWriteTestFile{f.file}, nil
}

type writeTestFile struct {
	billy.File
	t        *testing.T
	response *response
	events   []string
	limit    int
	writeErr error
	syncErr  error
	closeErr error
	seekErr  error
}

func (f *writeTestFile) record(event string) {
	f.t.Helper()
	if f.response.responded || f.response.writer.Len() != 0 {
		f.t.Errorf("reply emitted before %s", event)
	}
	f.events = append(f.events, event)
}

func (f *writeTestFile) Seek(offset int64, whence int) (int64, error) {
	f.record("seek")
	if f.seekErr != nil {
		return 0, f.seekErr
	}
	return f.File.Seek(offset, whence)
}

func (f *writeTestFile) Write(data []byte) (int, error) {
	f.record("write")
	if f.limit >= 0 && len(data) > f.limit {
		data = data[:f.limit]
	}
	n, err := f.File.Write(data)
	if err == nil {
		err = f.writeErr
	}
	return n, err
}

func (f *writeTestFile) Close() error {
	f.record("close")
	err := f.File.Close()
	if err == nil {
		err = f.closeErr
	}
	return err
}

type syncWriteTestFile struct{ *writeTestFile }

func (f *syncWriteTestFile) Sync() error {
	f.record("sync")
	if f.syncErr != nil {
		return f.syncErr
	}
	return f.File.(interface{ Sync() error }).Sync()
}

type writeTestHandler struct {
	Handler
	fs billy.Filesystem
}

func (h *writeTestHandler) FromHandle([]byte) (billy.Filesystem, []string, error) {
	return h.fs, []string{"file"}, nil
}

func TestWriteDurability(t *testing.T) {
	for _, how := range []writeStability{unstable, dataSync, fileSync} {
		for _, tc := range []struct {
			name        string
			count       uint32
			limit       int
			unsupported bool
			writeErr    error
			syncErr     error
			closeErr    error
			seekErr     error
			status      NFSStatus
			written     uint32
			events      []string
		}{
			{name: "full", count: 4, limit: -1, written: 4},
			{name: "partial", count: 4, limit: 2, written: 2},
			{name: "count-bounds-data", count: 2, limit: -1, written: 2},
			{name: "data-bounds-count", count: 8, limit: -1, written: 4},
			{name: "empty", count: 0, limit: -1},
			{name: "sync-io", count: 4, limit: -1, syncErr: syscall.EIO, status: NFSStatusIO},
			{name: "sync-space", count: 4, limit: -1, syncErr: &os.PathError{Op: "sync", Path: "file", Err: syscall.ENOSPC}, status: NFSStatusNoSPC},
			{name: "sync-quota", count: 4, limit: -1, syncErr: syscall.EDQUOT, status: NFSStatusDQuot},
			{name: "sync-size", count: 4, limit: -1, syncErr: syscall.EFBIG, status: NFSStatusFBig},
			{name: "sync-unsupported", count: 4, limit: -1, syncErr: billy.ErrNotSupported, status: NFSStatusIO},
			{name: "no-sync-interface", count: 4, limit: -1, unsupported: true, status: NFSStatusIO, events: []string{"close"}},
			{name: "short-write-error", count: 4, limit: 2, writeErr: io.ErrShortWrite, status: NFSStatusIO, events: []string{"seek", "write", "close"}},
			{name: "write-space", count: 4, limit: 2, writeErr: syscall.ENOSPC, status: NFSStatusNoSPC, events: []string{"seek", "write", "close"}},
			{name: "close-error", count: 4, limit: -1, closeErr: syscall.EIO, status: NFSStatusIO},
			{name: "seek-error", count: 4, limit: -1, seekErr: syscall.EIO, status: NFSStatusIO, events: []string{"seek", "close"}},
		} {
			t.Run(fmt.Sprintf("stability-%d/%s", how, tc.name), func(t *testing.T) {
				base := osfs.New(t.TempDir(), osfs.WithBoundOS())
				file, err := base.OpenFile("file", os.O_CREATE|os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
				body := new(bytes.Buffer)
				args := writeArgs{Handle: []byte("file"), Offset: 3, Count: tc.count, How: uint32(how), Data: []byte("data")}
				if err := xdr.Write(body, args); err != nil {
					t.Fatal(err)
				}
				server := &Server{ID: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}
				w := &response{conn: &conn{Server: server}, writer: new(bytes.Buffer), req: &request{xid: 42, Body: body}}
				recorded := &writeTestFile{t: t, response: w, limit: tc.limit, writeErr: tc.writeErr, syncErr: tc.syncErr, closeErr: tc.closeErr, seekErr: tc.seekErr}
				fs := &writeTestFS{Filesystem: base, file: recorded, unsupported: tc.unsupported}
				err = onWrite(context.Background(), w, &writeTestHandler{fs: fs})
				events := tc.events
				if events == nil {
					events = []string{"seek", "write", "sync", "close"}
				}
				if fs.opens != 1 || !reflect.DeepEqual(recorded.events, events) {
					t.Errorf("opens=%d events=%v, want one descriptor and %v", fs.opens, recorded.events, events)
				}
				if tc.status != NFSStatusOk {
					var statusErr *NFSStatusError
					if !errors.As(err, &statusErr) || statusErr.NFSStatus != tc.status {
						t.Fatalf("error=%v, want NFS status %v", err, tc.status)
					}
					if w.responded || w.writer.Len() != 0 {
						t.Fatal("failed WRITE emitted a stable acknowledgment")
					}
					if err := w.conn.err(context.Background(), w, err); err != nil {
						t.Fatal(err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
				var header [6]uint32
				if err := xdr.Read(w.writer, &header); err != nil {
					t.Fatal(err)
				}
				if header != [6]uint32{42, 1, 0, 0, 0, 0} {
					t.Fatalf("unexpected RPC reply header: %v", header)
				}
				status, err := xdr.ReadUint32(w.writer)
				if err != nil || status != uint32(tc.status) {
					t.Fatalf("wire status=%d, err=%v; want %d", status, err, tc.status)
				}
				if tc.status != NFSStatusOk {
					if !bytes.Equal(w.writer.Bytes(), make([]byte, 8)) {
						t.Fatalf("expected error WCC only, got %x", w.writer.Bytes())
					}
					return
				}
				var reply struct {
					PrePresent  uint32
					Pre         FileCacheAttribute
					PostPresent uint32
					Post        FileAttribute
					Count       uint32
					Committed   writeStability
					Verifier    [8]byte
				}
				if err := xdr.Read(w.writer, &reply); err != nil {
					t.Fatal(err)
				}
				if reply.PrePresent != 1 || reply.PostPresent != 1 || reply.Count != tc.written || reply.Committed != fileSync || reply.Verifier != server.ID || w.writer.Len() != 0 {
					t.Fatalf("unexpected WRITE reply: %+v (trailing bytes %d)", reply, w.writer.Len())
				}
			})
		}
	}
}
