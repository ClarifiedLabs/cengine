package storageservice

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	cc "dev.cengine/guest/internal/consumercompat"
	pc "dev.cengine/guest/internal/preparecompat"
	a "dev.cengine/guest/internal/storageauthority"
	c "dev.cengine/guest/internal/storagecontrol"
	p "dev.cengine/guest/internal/storagepki"
	d "dev.cengine/guest/internal/storageserver"
	w "dev.cengine/guest/internal/storagewire"
)

func wrongHelloROIdentity(t *testing.T, f *fixture) (a.DataHello, p.Identity) {
	control, join := f.connect(t)
	defer func() { control.Close(); join() }()
	volume := id(t)
	call(t, control, c.Request{CreateVolume: &a.CreateVolumeRequest{Operation: id(t), Store: f.ready.Store.ID, Volume: volume, Name: "original-ro"}})
	key, err := p.NewAttachmentKey(p.RuntimeRole)
	must(t, err)
	h := a.DataHello{Epoch: f.ready.ServiceEpoch, Binding: a.Binding{Store: f.ready.Store.ID, Volume: volume, Attachment: id(t), Container: a.ContainerID(strings.Repeat("a", 64)), Launch: id(t), Key: fingerprint(t, key), Role: a.RuntimeRole, Mode: a.ReadOnly}}
	call(t, control, c.Request{RegisterAttachment: &a.RegisterRequest{Operation: id(t), Binding: h.Binding}})
	binding, err := d.AttachmentBinding(h)
	must(t, err)
	csr, err := key.CSR(binding)
	must(t, err)
	raw, wait := serve(t, f.s.ServeAttachmentCSR)
	cert, err := RequestLifecycleAttachmentCertificate(context.Background(), raw, f.identity, f.ready, f.s.current.Grant.Identity, h, csr)
	must(t, err)
	must(t, wait())
	identity, err := cert.WithKey(key)
	must(t, err)
	return h, identity
}

// Actual current service, actual control-issued original RO leaf, completed TLS,
// actual decoded Hello and PKI rejection. No new CA or fake verifier is involved.
func TestIssuedIdentityWrongHelloActualTLS(t *testing.T) {
	for _, name := range []string{cc.WrongVolume, cc.WrongKey, cc.WrongRole, cc.WrongMode, cc.WrongEpoch} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			h, identity := wrongHelloROIdentity(t, f)
			other, _ := consumerIdentity(t, f)
			changed := h
			switch name {
			case cc.WrongVolume:
				changed.Binding.Volume = other.Binding.Volume
			case cc.WrongKey:
				changed.Binding.Key = other.Binding.Key
			case cc.WrongRole:
				changed.Binding.Role = a.PrepareRole
				changed.Binding.Prepare = id(t)
			case cc.WrongMode:
				changed.Binding.Mode = a.ReadWrite
			case cc.WrongEpoch:
				changed.Epoch = id(t)
			}
			q := consumerArm(t, f, h, identity, name)
			q.Version = 4
			_, err := f.s.ArmConsumerObservation(q)
			enabled := pc.CurrentProfile() == pc.FullProfile
			if enabled {
				must(t, err)
			} else if err == nil {
				t.Fatal("ordinary collector enabled")
			}
			raw, wait := serve(t, f.s.ServeData)
			writer := &consumerWrites{Conn: raw}
			conn := tls.Client(writer, consumerTLS(t, f, identity))
			must(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
			must(t, conn.Handshake())
			if !conn.ConnectionState().HandshakeComplete {
				t.Fatal("no key possession")
			}
			var greeting w.ServerHello
			must(t, w.ReadFrame(conn, &greeting))
			must(t, w.WriteFrame(conn, &w.ClientHello{Authority: changed, Profile: w.RequiredProfile()}))
			var root w.RootReply
			if w.ReadFrame(conn, &root) == nil {
				t.Fatal("wrong Hello admitted")
			}
			serverErr := wait()
			if serverErr == nil {
				t.Fatal("missing PKI rejection")
			}
			conn.Close()
			if !enabled {
				return
			}
			status, err := f.s.FinalizeConsumerObservation(q)
			must(t, err)
			must(t, cc.ValidateStatus(status))
			e := status.Evidence
			if status.State != "finalized" || e == nil || e.Hello == nil || *e.Hello != changed || e.Stage != "pki-verify-peer" || e.ErrorClass != "unauthorized" || e.RejectedLeafSHA256 != q.OriginalLeafSHA256 {
				t.Fatal(status)
			}
			data := writer.Buffer.Bytes()
			if e.ByteCount > uint64(len(data)) {
				t.Fatal("prefix overrun")
			}
			digest := sha256.New()
			digest.Write([]byte(d.TLSFailurePrefixDomain))
			digest.Write(data[:e.ByteCount])
			if hex.EncodeToString(digest.Sum(nil)) != e.PrefixSHA256 {
				t.Fatal("not actual client prefix")
			}
			// Returned snapshots are detached, including new nested Hello proof.
			e.Hello.Binding.Key = other.Binding.Key
			again, err := f.s.FinalizeConsumerObservation(q)
			must(t, err)
			if *again.Evidence.Hello != changed {
				t.Fatal("mutable sealed evidence")
			}
		})
	}
}

func TestIssuedIdentityWrongHelloCannotSubstituteLeafOrMutation(t *testing.T) {
	if pc.CurrentProfile() != pc.FullProfile {
		t.Skip("full-only passive collector")
	}
	for _, kind := range []string{"foreign-leaf", "wrong-mutation", "unknown-authority"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			original, identity := wrongHelloROIdentity(t, f)
			other, otherIdentity := consumerIdentity(t, f)
			q := consumerArm(t, f, original, identity, cc.WrongEpoch)
			q.Version = 4
			_, err := f.s.ArmConsumerObservation(q)
			must(t, err)
			changed := original
			changed.Epoch = id(t)
			switch kind {
			case "foreign-leaf":
				identity = otherIdentity
			case "wrong-mutation":
				changed = original
				changed.Binding.Key = other.Binding.Key
			case "unknown-authority":
				foreign := newFixture(t)
				_, identity = consumerIdentity(t, foreign)
			}
			raw, wait := serve(t, f.s.ServeData)
			cfg := consumerTLS(t, f, identity)
			// Ensure unknown-CA case sends its actual leaf rather than no certificate.
			cert := cfg.Certificates[0]
			cfg.Certificates = nil
			cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &cert, nil }
			conn := tls.Client(raw, cfg)
			must(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
			if conn.Handshake() == nil {
				var greeting w.ServerHello
				if w.ReadFrame(conn, &greeting) == nil {
					must(t, w.WriteFrame(conn, &w.ClientHello{Authority: changed, Profile: w.RequiredProfile()}))
					var root w.RootReply
					if w.ReadFrame(conn, &root) == nil {
						t.Fatal("bad tuple admitted")
					}
				}
			}
			if wait() == nil {
				t.Fatal("unrejected probe")
			}
			conn.Close()
			status, err := f.s.QueryConsumerObservation(q)
			must(t, err)
			if status.State != "failed" || status.Evidence != nil {
				t.Fatal("false proof", status)
			}
			if _, err = f.s.FinalizeConsumerObservation(q); err == nil {
				t.Fatal("sealed false proof")
			}
		})
	}
}
