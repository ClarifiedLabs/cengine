//go:build !linux || (!arm64 && !amd64)

package storagefuse

import "context"

type Mounted struct{}

func nativeMount(mountConfig) (*Mounted, error)            { return nil, ErrProfile }
func (*Mounted) Close() error                              { return ErrProfile }
func (*Mounted) CloseGracefully(context.Context) error     { return ErrProfile }
func (*Mounted) Err() error                                { return ErrProfile }
func (*Mounted) Mountpoint() string                        { return "" }
func (*Mounted) PrepareDenialDiagnostic() (string, uint64) { return "none", 0 }
func (*Mounted) Done() <-chan struct{}                     { done := make(chan struct{}); close(done); return done }

func (*Mounted) PrepareDenialDiagnosticDetails() PrepareDenialDetails {
	return (&denialTracker{}).details()
}
