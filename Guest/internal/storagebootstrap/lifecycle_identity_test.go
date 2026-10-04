package storagebootstrap

import (
	"context"
	a "dev.cengine/guest/internal/storageauthority"
	p "dev.cengine/guest/internal/storagepki"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func identityChallenge(t *testing.T, f *lifecycleSessionFixture, counter uint64) p.LifecycleChildIdentityChallenge {
	t.Helper()
	old := f.challenge(t, counter, p.LifecycleChildCandidate, f.owner.Grant).Fields()
	c, e := p.NewLifecycleChildIdentityChallenge(p.LifecycleChildIdentityChallengeFields{Version: p.LifecycleChildIdentityVersion, Greeting: old.Greeting, ChildAudit: old.ChildAudit, ChildUniqueID: old.ChildUniqueID, DaemonAudit: old.DaemonAudit, Counter: counter, Nonce: old.Nonce, RequestSHA256: base64.StdEncoding.EncodeToString(make([]byte, 32)), ExpiresUnixMS: old.ExpiresUnixMS})
	check(t, e)
	return c
}
func TestLifecycleIdentityPreGrantDoesNotPoisonRealGrant(t *testing.T) {
	for _, takeover := range []bool{false, true} {
		f := newLifecycleSessionIntent(t, takeover)
		greeting := f.s.greeting
		c := identityChallenge(t, f, 1)
		raw, e := f.s.rootProof(context.Background(), c.Canonical())
		check(t, e)
		r, e := p.DecodeLifecycleChildIdentityReply(raw)
		check(t, e)
		if !r.Verifies(c) {
			t.Fatal("proof")
		}
		if f.s.greeting != greeting || f.s.candidateOwner != (a.LifecycleGrant{}) || f.s.candidateRetirement != (a.LifecycleGrant{}) || f.s.owner.Grant != (a.LifecycleGrant{}) || f.s.retirement.Grant != (a.LifecycleGrant{}) || f.s.bootAttempted || f.s.rootBootSeen || f.s.client != nil {
			t.Fatal("identity mutated lifecycle")
		}
		if _, e = f.s.identityProof(context.Background(), c); e == nil {
			t.Fatal("identity replay")
		}
		if _, e = f.s.proof(context.Background(), f.challenge(t, 1, p.LifecycleChildCandidate, f.owner.Grant)); e == nil {
			t.Fatal("cross-family replay")
		}
		lifecycleSessionProof(t, f, f.challenge(t, 2, p.LifecycleChildCandidate, f.owner.Grant))
		if _, e = f.s.identityProof(context.Background(), identityChallenge(t, f, 2)); e == nil {
			t.Fatal("reverse cross-family replay")
		}
		f.owner = lifecycleSessionSign(t, f.rootPrivate, f.owner.Grant)
		f.initial = lifecycleSessionSign(t, f.rootPrivate, f.initial.Grant)
		check(t, f.s.bindGrant(f.owner))
		f.startAuthority(t)
		f.connect(t)
		if takeover {
			check(t, f.s.takeover(context.Background()))
		}
		lifecycleSessionProof(t, f, f.challenge(t, 3, p.LifecycleChildResult, f.owner.Grant))
	}
}
func TestLifecycleIdentityRejectsWithoutNativeEvidence(t *testing.T) {
	for _, kind := range []string{"daemon", "child", "unique", "greeting", "expired", "future", "unknown", "cross-family", "duplicate"} {
		t.Run(kind, func(t *testing.T) {
			f := newLifecycleSessionIntent(t, true)
			c := identityChallenge(t, f, 1)
			fields := c.Fields()
			switch kind {
			case "daemon":
				fields.DaemonAudit = fields.Nonce
			case "child":
				fields.ChildAudit = fields.Nonce
			case "unique":
				fields.ChildUniqueID++
			case "greeting":
				fields.Greeting.ChannelID = fields.Greeting.IncarnationID
			case "expired":
				fields.ExpiresUnixMS = uint64(time.Now().UnixMilli()) - 1
			case "future":
				fields.ExpiresUnixMS = uint64(time.Now().UnixMilli()) + 2*p.LifecycleChildLifetimeMS
			}
			c, e := p.NewLifecycleChildIdentityChallenge(fields)
			check(t, e)
			raw := c.Canonical()
			switch kind {
			case "unknown":
				raw = []byte(strings.Replace(string(raw), p.LifecycleChildIdentityVersion, "unknown", 1))
			case "cross-family":
				raw = []byte(strings.Replace(string(raw), p.LifecycleChildIdentityVersion, p.LifecycleChildVersion, 1))
			case "duplicate":
				raw = append([]byte(`{"version":"wrong",`), raw[1:]...)
			}
			if _, e = f.s.rootProof(context.Background(), raw); e == nil {
				t.Fatal("accepted", kind)
			}
			if f.s.highWater != 0 || f.s.candidateOwner != (a.LifecycleGrant{}) {
				t.Fatal("rejection mutated state")
			}
		})
	}
}
