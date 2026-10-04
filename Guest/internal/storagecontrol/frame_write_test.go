package storagecontrol

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"syscall"
	"testing"
)

type frameWriteFunc func([]byte) (int, error)

func (f frameWriteFunc) Write(p []byte) (int, error) { return f(p) }

type frameWriteCase struct {
	name string
	n    int
	err  error
	want error
}

func frameWriteCases(size int) []frameWriteCase {
	sentinel := errors.New("write failure")
	cases := []frameWriteCase{
		{"zero-nil", 0, nil, io.ErrShortWrite},
		{"negative-nil", -1, nil, io.ErrShortWrite},
		{"oversized-nil", size + 1, nil, io.ErrShortWrite},
	}
	for _, fault := range []struct {
		name string
		err  error
	}{
		{"sentinel", sentinel},
		{"EIO", syscall.EIO},
		{"ENOSPC", syscall.ENOSPC},
		{"wrapped-EIO", fmt.Errorf("write: %w", syscall.EIO)},
		{"wrapped-ENOSPC", fmt.Errorf("write: %w", syscall.ENOSPC)},
	} {
		for _, progress := range []struct {
			name string
			n    int
		}{
			{"zero", 0},
			{"partial", 1},
			{"full", size},
			{"negative", -1},
			{"oversized", size + 1},
		} {
			want := fault.err
			if progress.n < 0 || progress.n > size {
				want = io.ErrShortWrite
			}
			cases = append(cases, frameWriteCase{progress.name + "-" + fault.name, progress.n, fault.err, want})
		}
	}
	return cases
}

func TestWriteFullErrorContract(t *testing.T) {
	data := []byte("abcdef")
	for _, tc := range frameWriteCases(len(data)) {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			w := frameWriteFunc(func(p []byte) (int, error) {
				calls++
				if calls != 1 {
					t.Fatal("write retried after terminal result")
				}
				if !bytes.Equal(p, data) {
					t.Fatalf("write input = %q, want %q", p, data)
				}
				return tc.n, tc.err
			})
			// Exact identity preserves the original wrapper as well as its errno.
			if err := writeFull(w, data); err != tc.want {
				t.Fatalf("writeFull = %v, want original %v", err, tc.want)
			}
			if calls != 1 {
				t.Fatalf("write calls = %d, want 1", calls)
			}
		})
	}
}

func TestWriteFullProgress(t *testing.T) {
	for _, size := range []int{0, 1, 3, 6} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			data := []byte("abcdef")[:size]
			var out bytes.Buffer
			calls := 0
			w := frameWriteFunc(func(p []byte) (int, error) {
				calls++
				if !bytes.Equal(p, data[out.Len():]) {
					t.Fatalf("write input = %q, want remaining %q", p, data[out.Len():])
				}
				return out.Write(p[:min(2, len(p))])
			})
			if err := writeFull(w, data); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(out.Bytes(), data) || calls != (size+1)/2 {
				t.Fatalf("output = %q, calls = %d, size = %d", out.Bytes(), calls, size)
			}
		})
	}
}

func TestWriteFrameErrorContractAndBudget(t *testing.T) {
	for _, part := range []struct {
		name string
		call int
		data []byte
	}{
		{"header", 1, []byte{0, 0, 0, 2}},
		{"body", 2, []byte("{}")},
	} {
		for _, tc := range frameWriteCases(len(part.data)) {
			t.Run(part.name+"/"+tc.name, func(t *testing.T) {
				const max = 1024
				const held = 7
				var b budget
				if !b.take(held) {
					t.Fatal("reserve unrelated budget")
				}
				t.Cleanup(func() {
					if b.used != held {
						t.Errorf("frame budget = %d, want unrelated reservation %d", b.used, held)
					}
					b.release(held)
					if b.used != 0 {
						t.Errorf("budget after cleanup = %d, want 0", b.used)
					}
				})
				calls := 0
				w := frameWriteFunc(func(p []byte) (int, error) {
					calls++
					if calls > part.call {
						t.Fatal("frame write continued after terminal result")
					}
					if b.used != held+max {
						t.Fatalf("frame budget during write = %d, want %d", b.used, held+max)
					}
					if calls < part.call {
						if !bytes.Equal(p, []byte{0, 0, 0, 2}) {
							t.Fatalf("header = %v", p)
						}
						return len(p), nil
					}
					if !bytes.Equal(p, part.data) {
						t.Fatalf("write input = %v, want %v", p, part.data)
					}
					return tc.n, tc.err
				})
				if err := writeFrame(w, struct{}{}, max, &b); err != tc.want {
					t.Fatalf("writeFrame = %v, want original %v", err, tc.want)
				}
				if calls != part.call {
					t.Fatalf("write calls = %d, want %d", calls, part.call)
				}
			})
		}
	}
}
