package nfs

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/osfs"
	"github.com/willscott/go-nfs-client/nfs/rpc"
	"github.com/willscott/go-nfs-client/nfs/xdr"
)

type createDescriptorFS struct {
	billy.Filesystem
	opens     int
	truncates []int64
}

func (f *createDescriptorFS) OpenFile(name string, flags int, mode os.FileMode) (billy.File, error) {
	f.opens++
	// Model an unprivileged caller: creation returns a writable descriptor, but
	// reopening a freshly created 0444/0000 file for writing must fail. Keeping
	// this explicit makes the regression useful even in a root test runner.
	if f.opens > 1 {
		return nil, os.ErrPermission
	}
	file, err := f.Filesystem.OpenFile(name, flags, mode)
	if err != nil {
		return nil, err
	}
	return &createDescriptorFile{File: file, fs: f}, nil
}

type createDescriptorFile struct {
	billy.File
	fs *createDescriptorFS
}

func (f *createDescriptorFile) Truncate(size int64) error {
	f.fs.truncates = append(f.fs.truncates, size)
	return f.File.Truncate(size)
}

type createDescriptorHandler struct {
	Handler
	fs *createDescriptorFS
}

func (h *createDescriptorHandler) FromHandle([]byte) (billy.Filesystem, []string, error) {
	return h.fs, []string{"."}, nil
}
func (h *createDescriptorHandler) ToHandle(_ billy.Filesystem, path []string) []byte {
	return []byte(h.fs.Join(path...))
}
func (h *createDescriptorHandler) Change(billy.Filesystem) billy.Change {
	return nil // These modes are already installed by OpenFile; no chmod is needed.
}

func TestCreateAppliesSizeThroughOriginalDescriptor(t *testing.T) {
	for _, mode := range []uint32{0444, 0000} {
		t.Run(fmt.Sprintf("mode-%04o", mode), func(t *testing.T) {
			fs := &createDescriptorFS{Filesystem: osfs.New(t.TempDir(), osfs.WithBoundOS())}
			h := &createDescriptorHandler{fs: fs}
			body := new(bytes.Buffer)
			// CREATE UNCHECKED, explicit mode and size=0, no owner/group/times.
			for _, value := range []interface{}{[]byte("root"), "file", uint32(0), uint32(1), mode, uint32(0), uint32(0), uint32(1), uint64(0), uint32(0), uint32(0)} {
				if err := xdr.Write(body, value); err != nil {
					t.Fatal(err)
				}
			}
			c := &conn{Server: &Server{Handler: h}}
			w := &response{conn: c, writer: new(bytes.Buffer), errorFmt: basicErrorFormatter,
				req: &request{xid: 42, Header: rpc.Header{Prog: nfsServiceID, Proc: uint32(NFSProcedureCreate)}, Body: &io.LimitedReader{R: body, N: int64(body.Len())}}}
			if err := c.handle(context.Background(), w); err != nil {
				t.Fatal(err)
			}
			if w.err != nil {
				t.Fatalf("CREATE with mode %04o and size=0 failed: %v", mode, w.err)
			}
			if fs.opens != 1 || len(fs.truncates) != 1 || fs.truncates[0] != 0 {
				t.Fatalf("size must use original descriptor: opens=%d truncates=%v", fs.opens, fs.truncates)
			}
			info, err := fs.Lstat("file")
			if err != nil {
				t.Fatal(err)
			}
			if uint32(info.Mode().Perm()) != mode || info.Size() != 0 {
				t.Fatalf("created file: mode=%04o size=%d", info.Mode().Perm(), info.Size())
			}
		})
	}
}
