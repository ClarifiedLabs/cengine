//go:build !cengine_prepare_full_compat

package storagebootstrap

import "context"

func (s *lifecycleSession) publicTakeoverReplay(context.Context, []byte) ([]byte, error) {
	return nil, ErrProtocol
}
