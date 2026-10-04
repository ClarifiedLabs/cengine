package storagecontrol

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestFrameEOFBoundaryAndBudget(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
		want error
	}{
		{"boundary", nil, io.EOF},
		{"partial-header", []byte{0, 0}, io.ErrUnexpectedEOF},
		{"missing-body", []byte{0, 0, 0, 2}, io.ErrUnexpectedEOF},
		{"partial-body", []byte{0, 0, 0, 2, '{'}, io.ErrUnexpectedEOF},
		{"complete", []byte{0, 0, 0, 2, '{', '}'}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var b budget
			var value struct{}
			err := readFrame(bytes.NewReader(tc.data), &value, 1024, &b)
			if !errors.Is(err, tc.want) {
				t.Fatalf("readFrame = %v, want %v", err, tc.want)
			}
			if b.used != 0 {
				t.Fatalf("frame budget leaked: %d", b.used)
			}
		})
	}
}
