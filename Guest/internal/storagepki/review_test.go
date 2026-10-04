package storagepki

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net"
	"testing"
	"time"
)

func TestCSRRejectsHiddenSignedFields(t *testing.T) {
	f := setup(t)
	der, e := f.server.key.CSR(serverBinding(t))
	der = must(t, der, e)
	csr, e := x509.ParseCertificateRequest(der)
	csr = must(t, csr, e)
	for name, mutate := range map[string]func(*requestInfo){
		"ignoredChallengePassword": func(info *requestInfo) {
			text, e := asn1.Marshal("password")
			text = must(t, text, e)
			extra, e := asn1.Marshal(requestAttribute{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}, []asn1.RawValue{{FullBytes: text}}})
			extra = must(t, extra, e)
			info.Attributes = append(info.Attributes, asn1.RawValue{FullBytes: extra})
		},
		"ignoredMalformedAttribute": func(info *requestInfo) {
			info.Attributes = append(info.Attributes, asn1.RawValue{FullBytes: []byte{0x30, 0}})
		},
		"extraExtensionValue": func(info *requestInfo) {
			var attr requestAttribute
			if _, e := asn1.Unmarshal(info.Attributes[0].FullBytes, &attr); e != nil {
				t.Fatal(e)
			}
			attr.Values = append(attr.Values, attr.Values[0])
			d, e := asn1.Marshal(attr)
			d = must(t, d, e)
			info.Attributes[0] = asn1.RawValue{FullBytes: d}
		},
		"version": func(info *requestInfo) { info.Version = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			var info requestInfo
			if _, e := asn1.Unmarshal(csr.RawTBSCertificateRequest, &info); e != nil {
				t.Fatal(e)
			}
			mutate(&info)
			tbs, e := asn1.Marshal(info)
			tbs = must(t, tbs, e)
			sig := ed25519.Sign(f.server.key.private(), tbs)
			signed, e := asn1.Marshal(struct {
				Info      asn1.RawValue
				Algorithm pkix.AlgorithmIdentifier
				Signature asn1.BitString
			}{asn1.RawValue{FullBytes: tbs}, pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 3, 101, 112}}, asn1.BitString{Bytes: sig, BitLength: len(sig) * 8}})
			signed = must(t, signed, e)
			// These carry a cryptographically valid signature; rejection is request policy.
			parsed, e := x509.ParseCertificateRequest(signed)
			if e == nil && parsed.CheckSignature() != nil {
				t.Fatal("invalid fixture signature")
			}
			if _, e := f.issuer.IssueServer(signed, serverBinding(t), f.now, time.Hour); e == nil {
				t.Fatal("hidden signed field accepted")
			}
		})
	}
}

func TestNativeTLSClientFactoryRejectsServerPinAndScope(t *testing.T) {
	f := setup(t)
	differentStore, e := NewServerBinding(StoreID(other), epoch)
	differentStore = must(t, differentStore, e)
	differentEpoch, e := NewServerBinding(store, ServiceEpoch(other))
	differentEpoch = must(t, differentEpoch, e)
	for _, tc := range []struct {
		name     string
		binding  Binding
		pin      Fingerprint
		accepted bool
	}{
		{"matching", serverBinding(t), f.serverPin, true},
		{"wrongPin", serverBinding(t), f.controllerPin, false},
		{"wrongStore", differentStore, f.serverPin, false},
		{"wrongServiceEpoch", differentEpoch, f.serverPin, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sc, e := ServerTLSConfig(f.server, f.issuer.Root())
			sc = must(t, sc, e)
			for _, id := range []Identity{f.controller, f.attachment} {
				for range 2 {
					ss, cs, err := handshakeClient(sc, func(raw net.Conn) *tls.Conn {
						if id.cert.binding.role == ControllerRole {
							conn, err := NewControllerTLSClient(raw, id, f.issuer.Root(), tc.binding, tc.pin)
							return must(t, conn, err)
						}
						cc, err := ClientTLSConfig(id, f.issuer.Root(), tc.binding, tc.pin)
						return tls.Client(raw, must(t, cc, err))
					}, nil)
					if (err == nil) != tc.accepted {
						t.Fatalf("role=%s accept=%v err=%v", id.cert.binding.role, tc.accepted, err)
					}
					if err == nil {
						if ss.Version != tls.VersionTLS13 || cs.Version != tls.VersionTLS13 || ss.DidResume || cs.DidResume {
							t.Fatal("bad TLS version/resume")
						}
						if id.cert.binding.role == ControllerRole && VerifyController(ss, f.issuer.Root(), controllerBinding(t), f.controllerPin) != nil {
							t.Fatal("wrong controller identity")
						}
					}
				}
			}
		})
	}
}

func TestRoleGuardsAndPrepareScope(t *testing.T) {
	f := setup(t)
	if _, e := ServerTLSConfig(f.controller, f.issuer.Root()); e == nil {
		t.Fatal("controller as server")
	}
	if _, e := ClientTLSConfig(f.server, f.issuer.Root(), serverBinding(t), f.serverPin); e == nil {
		t.Fatal("server as client")
	}
	sc, cc := configs(t, f, f.controller)
	ss, cs, e := handshake(sc, cc, nil)
	if e != nil {
		t.Fatal(e)
	}
	if VerifyServer(cs, f.issuer.Root(), controllerBinding(t), f.serverPin) == nil || VerifyController(ss, f.issuer.Root(), serverBinding(t), f.controllerPin) == nil || VerifyAttachment(ss, f.issuer.Root(), controllerBinding(t), f.controllerPin) == nil {
		t.Fatal("role-confused verifier")
	}
	a := tuple()
	a.Role = PrepareRole
	a.Prepare = PrepareID(other)
	b := attachmentBinding(t, a)
	key, e := NewAttachmentKey(PrepareRole)
	key = must(t, key, e)
	id := issue(t, f.issuer, b, key, f.now)
	pin, e := key.Fingerprint()
	pin = must(t, pin, e)
	sc, cc = configs(t, f, id)
	ss, _, e = handshake(sc, cc, func(s tls.ConnectionState) error { return VerifyAttachment(s, f.issuer.Root(), b, pin) })
	if e != nil {
		t.Fatal(e)
	}
	a.Prepare = PrepareID(store)
	wrong := attachmentBinding(t, a)
	if VerifyAttachment(ss, f.issuer.Root(), wrong, pin) == nil {
		t.Fatal("wrong prepare accepted")
	}
	wrong, e = NewAttachmentBinding(store, ServiceEpoch(other), tuple())
	wrong = must(t, wrong, e)
	sc, cc = configs(t, f, f.attachment)
	if _, _, e := handshake(sc, cc, func(s tls.ConnectionState) error { return VerifyAttachment(s, f.issuer.Root(), wrong, f.attachmentPin) }); e == nil {
		t.Fatal("wrong attachment service epoch accepted")
	}
}

func TestControllerRenewalKeepsIndependentlyChosenKeyAndEpoch(t *testing.T) {
	f := setup(t)
	renewed := issue(t, f.issuer, controllerBinding(t), f.controller.key, f.now.Add(time.Minute))
	if !renewed.key.PublicKey().Equal(f.controller.key.PublicKey()) || renewed.cert.Binding() != controllerBinding(t) {
		t.Fatal("renewal changed identity")
	}
	next, e := NewControllerBinding(store, 8)
	next = must(t, next, e)
	// PKI does not attest that epoch 8 was authorized: registry/grant checks remain
	// mandatory even when a valid certificate binds the same key to that claim.
	claimed := issue(t, f.issuer, next, f.controller.key, f.now)
	sc, cc := configs(t, f, claimed)
	if _, _, e := handshake(sc, cc, func(s tls.ConnectionState) error {
		return VerifyController(s, f.issuer.Root(), controllerBinding(t), f.controllerPin)
	}); e == nil {
		t.Fatal("certificate substituted for expected epoch")
	}
}
