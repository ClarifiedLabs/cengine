package storagefuse

import (
	"io"
	"syscall"
	"testing"

	"github.com/hanwen/go-fuse/v2/fuse"
)

func TestInterruptDeliveryPolicy(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reply fuse.ReplyDelivery
		clean bool
	}{
		{"matched", fuse.ReplyDelivery{Unique: 11, Opcode: 36, Suppressed: true}, true},
		{"unmatched", fuse.ReplyDelivery{Unique: 11, Opcode: 36, Status: fuse.EAGAIN, Expected: 16, Bytes: 16}, true},
		{"completed-before-interrupt-reply", fuse.ReplyDelivery{Unique: 11, Opcode: 36, Status: fuse.EAGAIN, Expected: 16, Bytes: -1, Err: syscall.ENOENT}, true},
		{"zero-unique", fuse.ReplyDelivery{Opcode: 36, Suppressed: true}, false},
		{"control-short", fuse.ReplyDelivery{Unique: 11, Opcode: 36, Status: fuse.EAGAIN, Expected: 16, Bytes: 15, Err: io.ErrShortWrite}, false},
		{"control-io", fuse.ReplyDelivery{Unique: 11, Opcode: 36, Status: fuse.EAGAIN, Expected: 16, Bytes: -1, Err: syscall.EIO}, false},
		{"control-status", fuse.ReplyDelivery{Unique: 11, Opcode: 36, Status: fuse.EIO, Expected: 16, Bytes: 16}, false},
		{"control-suppressed-error", fuse.ReplyDelivery{Unique: 11, Opcode: 36, Status: fuse.EAGAIN, Suppressed: true}, false},
		{"control-interrupted", fuse.ReplyDelivery{Unique: 11, Opcode: 36, Suppressed: true, Interrupted: true}, false},
		{"control-ambiguous-enoent", fuse.ReplyDelivery{Unique: 11, Opcode: 36, Status: fuse.EAGAIN, Expected: 16, Bytes: 1, Err: syscall.ENOENT}, false},
		{"delivered-open", fuse.ReplyDelivery{Unique: 10, Opcode: 14, Expected: 32, Bytes: 32, Interrupted: true}, true},
		{"delivered-lookup", fuse.ReplyDelivery{Unique: 10, Opcode: 1, Expected: 144, Bytes: 144, Interrupted: true}, true},
		{"delivered-negative", fuse.ReplyDelivery{Unique: 10, Opcode: 1, Status: fuse.ENOENT, Expected: 16, Bytes: 16, Interrupted: true}, true},
		{"lost-open", fuse.ReplyDelivery{Unique: 10, Opcode: 14, Expected: 32, Bytes: -1, Err: syscall.ENOENT, Interrupted: true}, false},
		{"suppressed-open", fuse.ReplyDelivery{Unique: 10, Opcode: 14, Suppressed: true, Interrupted: true}, false},
		{"short-open", fuse.ReplyDelivery{Unique: 10, Opcode: 14, Expected: 32, Bytes: 16, Interrupted: true}, false},
		{"operation-eintr", fuse.ReplyDelivery{Unique: 10, Opcode: 14, Status: fuse.EINTR, Expected: 16, Bytes: 16, Interrupted: true}, false},
		{"lost-release", fuse.ReplyDelivery{Unique: 10, Opcode: 18, Expected: 16, Bytes: -1, Err: syscall.ENOENT}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, client := fixture()
			f.observeReply(tc.reply)
			if got := client.aborted == 0; got != tc.clean {
				t.Fatalf("clean=%v, want %v: %+v", got, tc.clean, tc.reply)
			}
		})
	}
}

func TestInterruptedDirectoryDeliveryRetainsAccounting(t *testing.T) {
	d := directoryReleases{limit: 1}
	if err := d.beginOpen(10); err != nil {
		t.Fatal(err)
	}
	if err := d.returnedOpen(10, 7, fuse.OK); err != nil {
		t.Fatal(err)
	}
	r := fuse.ReplyDelivery{Unique: 10, Opcode: 27, Expected: 32, Bytes: 32, Interrupted: true}
	if err := d.deliveredOpen(r); err != nil {
		t.Fatal(err)
	}
	if len(d.opens) != 0 || len(d.handles) != 1 {
		t.Fatal("open accounting changed")
	}
	if err := d.releasing(12, 7); err != nil {
		t.Fatal(err)
	}
	if err := d.returned(12); err != nil {
		t.Fatal(err)
	}
	r = releaseReply(12)
	r.Interrupted = true
	if err := d.delivered(r, false); err != nil {
		t.Fatal(err)
	}
	if len(d.handles) != 0 || len(d.requests) != 0 || d.completed != 1 {
		t.Fatal("release accounting changed")
	}
	if err := d.delivered(r, false); err == nil {
		t.Fatal("duplicate accepted", err)
	}
}
