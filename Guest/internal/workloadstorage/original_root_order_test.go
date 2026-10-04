package workloadstorage

import (
	"context"
	"errors"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storageclient"
)

// These scheduling fakes test owner ordering, not authentic READ/admission proof.
// Real grants, wire sequencing, and authority denial are tested independently.
type rootProbeOrderAttachment struct {
	rootNoWireAttachment
	terminal error
	attempt  func() (c.OriginalConsumerRootRequest, error)
	replay   func() (c.OriginalConsumerRootReplay, error)
}

func (m *rootProbeOrderAttachment) Err() error { return m.terminal }
func (m *rootProbeOrderAttachment) OriginalConsumerRootAttempt(context.Context, a.DataHello) (c.OriginalConsumerRootRequest, error) {
	return m.attempt()
}
func (m *rootProbeOrderAttachment) ReplayOriginalConsumerRead(context.Context, a.DataHello, *c.OriginalConsumerReadGrant, *c.OriginalConsumerReadGrant) (c.OriginalConsumerRootReplay, error) {
	return m.replay()
}

func TestOriginalDeniedMountRequiresActualJoin(t *testing.T) {
	for _, mode := range []string{"joined", "clean", "terminal-only", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			m := &rootProbeOrderAttachment{terminal: c.ErrClosed}
			m.done = make(chan struct{})
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			if mode != "terminal-only" {
				close(m.done)
			}
			if mode == "clean" {
				m.terminal = nil
			}
			if mode == "canceled" {
				cancel()
			}
			if err := waitOriginalDeniedMount(ctx, m); (err == nil) != (mode == "joined") {
				t.Fatal("terminal flag/cancellation substituted for joined failed mount", err)
			}
		})
	}
}

func TestOriginalRootProbeReplayPrecedesDenialAndJoinsCascade(t *testing.T) {
	for _, fault := range []string{"none", "cross-mount", "replay-failed", "wrong-target", "source-success", "source-protocol", "source-sequence", "source-unjoined", "target-unjoined", "target-clean"} {
		t.Run(fault, func(t *testing.T) {
			source, target := &rootProbeOrderAttachment{}, &rootProbeOrderAttachment{}
			source.done, target.done = make(chan struct{}), make(chan struct{})
			pair := &originalRootPair{attachments: [2]Attachment{source, target}, readers: [2]originalReadAttachment{source, target},
				grants: [2]*c.OriginalConsumerReadGrant{{}, {}}, authority: [2]a.DataHello{{Epoch: "source"}, {Epoch: "target"}}}
			pair.positive.Source.RootRequest.Node = 1
			pair.positive.Source.Read.RequestSequence = 2
			pair.positive.Target.Read.ContentSHA256 = "target-digest"
			var replayed, attempted bool
			target.replay = func() (c.OriginalConsumerRootReplay, error) {
				if attempted {
					t.Fatal("target used after source terminal cascade")
				}
				replayed = true
				if fault == "replay-failed" {
					return c.OriginalConsumerRootReplay{}, c.ErrProtocol
				}
				value := c.OriginalConsumerRootReplay{Source: pair.authority[0], Target: pair.authority[1], ContentSHA256: pair.positive.Target.Read.ContentSHA256}
				if fault == "wrong-target" {
					value.Target = pair.authority[0]
				}
				return value, nil
			}
			source.attempt = func() (c.OriginalConsumerRootRequest, error) {
				if !replayed {
					t.Fatal("denial preceded target replay")
				}
				attempted = true
				request := c.OriginalConsumerRootRequest{Node: 1, RequestSequence: 3}
				if fault == "source-sequence" {
					request.RequestSequence = 2
				}
				if fault == "cross-mount" || fault == "source-success" {
					return request, nil
				}
				if fault == "source-protocol" {
					return request, c.ErrProtocol
				}
				source.terminal, target.terminal = c.ErrClosed, c.ErrClosed
				if fault == "target-clean" {
					target.terminal = nil
				}
				if fault != "source-unjoined" {
					close(source.done)
				}
				if fault != "target-unjoined" {
					close(target.done)
				}
				return request, c.ErrClosed
			}
			o := &originalConsumer{roots: pair, arm: OriginalConsumerArm{CaseName: "retired-root-grant-replay"}}
			if fault == "cross-mount" {
				o.arm.CaseName = fault + "-root-grant"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			result, err := o.probeRoots(ctx, OriginalConsumerEvidence{Roots: &pair.positive})
			if fault == "none" || fault == "cross-mount" {
				if err != nil || result.Roots.Replay == nil || !attempted {
					t.Fatal("lost joined observations", err)
				}
			} else if err == nil {
				t.Fatal("invalid/unjoined observation accepted")
			}
			if fault == "replay-failed" || fault == "wrong-target" {
				if attempted {
					t.Fatal("continued after invalid target replay")
				}
			}
			if fault == "source-unjoined" || fault == "target-unjoined" {
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("missing actual join bound", err)
				}
			}
		})
	}
}
