package storagepki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	store StoreID      = "11111111-1111-4111-8111-111111111111"
	epoch ServiceEpoch = "22222222-2222-4222-8222-222222222222"
	other              = "33333333-3333-4333-8333-333333333333"
)

func must[T any](t *testing.T, v T, err error) T {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// Go does not expand a multi-result call alongside t; these short helpers keep
// fixture creation explicit and all failures fatal.
func serverBinding(t *testing.T) Binding {
	t.Helper()
	b, e := NewServerBinding(store, epoch)
	return must(t, b, e)
}
func controllerBinding(t *testing.T) Binding {
	t.Helper()
	b, e := NewControllerBinding(store, 7)
	return must(t, b, e)
}
func tuple() AttachmentTuple {
	return AttachmentTuple{Attachment: AttachmentID(other), Volume: VolumeID(other), Role: RuntimeRole, Mode: ReadWrite, Container: ContainerID(strings.Repeat("a", 64)), Launch: LaunchID(other)}
}
func attachmentBinding(t *testing.T, a AttachmentTuple) Binding {
	t.Helper()
	b, e := NewAttachmentBinding(store, epoch, a)
	return must(t, b, e)
}

type fixture struct {
	issuer                                  Issuer
	bootstrapPrivate                        ed25519.PrivateKey
	now                                     time.Time
	server, controller, attachment          Identity
	serverPin, controllerPin, attachmentPin Fingerprint
}

func issue(t *testing.T, i Issuer, b Binding, k Key, now time.Time) Identity {
	t.Helper()
	csr, e := k.CSR(b)
	csr = must(t, csr, e)
	var c Certificate
	switch b.role {
	case ServerRole:
		c, e = i.IssueServer(csr, b, now, time.Hour)
	case ControllerRole:
		c, e = i.IssueController(csr, b, now, time.Hour)
	default:
		c, e = i.IssueAttachment(csr, b, now, time.Hour)
	}
	c = must(t, c, e)
	id, e := c.WithKey(k)
	return must(t, id, e)
}
func setup(t *testing.T) fixture {
	t.Helper()
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	boot, e := NewBootstrapPublicKey(pub)
	boot = must(t, boot, e)
	now := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	ca, e := NewIssuer(now, MaxValidity, boot)
	ca = must(t, ca, e)
	sk, e := NewServerKey()
	sk = must(t, sk, e)
	ck, e := NewControllerKey()
	ck = must(t, ck, e)
	ak, e := NewAttachmentKey(RuntimeRole)
	ak = must(t, ak, e)
	sp, e := sk.Fingerprint()
	sp = must(t, sp, e)
	cp, e := ck.Fingerprint()
	cp = must(t, cp, e)
	ap, e := ak.Fingerprint()
	ap = must(t, ap, e)
	return fixture{ca, priv, now, issue(t, ca, serverBinding(t), sk, now), issue(t, ca, controllerBinding(t), ck, now), issue(t, ca, attachmentBinding(t, tuple()), ak, now), sp, cp, ap}
}
func TestBindings(t *testing.T) {
	if got := serverBinding(t).URI(); got != "spiffe://cengine.storage/store/"+string(store)+"/server/"+string(epoch) {
		t.Fatal(got)
	}
	if got := controllerBinding(t).URI(); got != "spiffe://cengine.storage/store/"+string(store)+"/controller/7" {
		t.Fatal(got)
	}
	want := "spiffe://cengine.storage/store/" + string(store) + "/attachment/" + other + "/service/" + string(epoch) + "/volume/" + other + "/role/runtime/mode/read-write/container/" + strings.Repeat("a", 64) + "/launch/" + other + "/prepare/-"
	if attachmentBinding(t, tuple()).URI() != want {
		t.Fatal("noncanonical tuple")
	}
	for _, s := range []string{"", "AAAAAAAA-1111-4111-8111-111111111111", string(store) + "/..", "11111111-1111-1111-8111-111111111111", "11111111-1111-4111-7111-111111111111"} {
		if _, e := NewServerBinding(StoreID(s), epoch); e == nil {
			t.Fatalf("accepted %q", s)
		}
	}
	if _, e := NewControllerBinding(store, 0); e == nil {
		t.Fatal("zero controller epoch")
	}
	for _, mutate := range []func(*AttachmentTuple){func(a *AttachmentTuple) { a.Role = ControllerRole }, func(a *AttachmentTuple) { a.Mode = "rw" }, func(a *AttachmentTuple) { a.Container = "short" }, func(a *AttachmentTuple) { a.Launch = "" }, func(a *AttachmentTuple) { a.Prepare = PrepareID(other) }, func(a *AttachmentTuple) { a.Role = PrepareRole }} {
		a := tuple()
		mutate(&a)
		if _, e := NewAttachmentBinding(store, epoch, a); e == nil {
			t.Fatal("invalid tuple accepted")
		}
	}
	a := tuple()
	a.Role = PrepareRole
	a.Prepare = PrepareID(other)
	a.Mode = ReadOnly
	if b := attachmentBinding(t, a); !strings.HasSuffix(b.URI(), "/prepare/"+other) {
		t.Fatal(b)
	}
}
func TestFreshRoleKeysAndValueCopies(t *testing.T) {
	f := setup(t)
	seen := map[Fingerprint]bool{}
	for range 32 {
		k, e := NewControllerKey()
		k = must(t, k, e)
		fp, e := k.Fingerprint()
		fp = must(t, fp, e)
		if seen[fp] {
			t.Fatal("reused random key")
		}
		seen[fp] = true
		id, e := NewUUID()
		id = must(t, id, e)
		if !uuid(id) {
			t.Fatal(id)
		}
	}
	if f.serverPin == f.controllerPin || f.serverPin == f.attachmentPin || f.controllerPin == f.attachmentPin {
		t.Fatal("shared role key")
	}
	if _, e := f.controller.key.CSR(serverBinding(t)); e == nil {
		t.Fatal("cross-role CSR")
	}
	if _, e := NewAttachmentKey(ServerRole); e == nil {
		t.Fatal("server attachment key")
	}
	if _, e := (Key{}).CSR(serverBinding(t)); e == nil {
		t.Fatal("zero key")
	}
	pub := f.server.key.PublicKey()
	clear(pub)
	fp, e := f.server.key.Fingerprint()
	if e != nil || fp != f.serverPin {
		t.Fatal("aliased public key")
	}
	der := f.issuer.Root().DER()
	clear(der)
	if _, e := ParseRootDER(f.issuer.Root().DER()); e != nil {
		t.Fatal(e)
	}
	for _, secret := range []any{f.server.key, f.server, f.issuer} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if !strings.Contains(fmt.Sprintf(format, secret), "REDACTED") {
				t.Fatal("unredacted credential")
			}
		}
		b, e := json.Marshal(secret)
		if e != nil || string(b) != "{}" {
			t.Fatal("implicit serialization")
		}
	}
}
func TestCSRValidation(t *testing.T) {
	f := setup(t)
	b := serverBinding(t)
	good, e := f.server.key.CSR(b)
	good = must(t, good, e)
	badSig := bytes.Clone(good)
	badSig[len(badSig)-1] ^= 1
	otherBinding, e := NewServerBinding(StoreID(other), epoch)
	otherBinding = must(t, otherBinding, e)
	u, _ := url.Parse(b.URI())
	foreign, _ := url.Parse(otherBinding.URI())
	csr := func(template *x509.CertificateRequest, key any) []byte {
		d, e := x509.CreateCertificateRequest(rand.Reader, template, key)
		return must(t, d, e)
	}
	eck, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	eck = must(t, eck, e)
	cases := map[string][]byte{
		"empty": nil, "malformed": {1, 2, 3}, "signature": badSig, "trailing": append(bytes.Clone(good), 0), "oversize": make([]byte, MaxDERSize+1),
		"ecdsa":     csr(&x509.CertificateRequest{DNSNames: []string{ServerName}, URIs: []*url.URL{u}}, eck),
		"wrongURI":  csr(&x509.CertificateRequest{DNSNames: []string{ServerName}, URIs: []*url.URL{foreign}}, f.server.key.private()),
		"extraURI":  csr(&x509.CertificateRequest{DNSNames: []string{ServerName}, URIs: []*url.URL{u, foreign}}, f.server.key.private()),
		"wrongDNS":  csr(&x509.CertificateRequest{DNSNames: []string{"other.invalid"}, URIs: []*url.URL{u}}, f.server.key.private()),
		"subject":   csr(&x509.CertificateRequest{Subject: pkix.Name{CommonName: "unexpected"}, DNSNames: []string{ServerName}, URIs: []*url.URL{u}}, f.server.key.private()),
		"requestCA": csr(&x509.CertificateRequest{DNSNames: []string{ServerName}, URIs: []*url.URL{u}, ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Value: []byte{0x30, 3, 1, 1, 0xff}}}}, f.server.key.private()),
		"helperKey": csr(&x509.CertificateRequest{DNSNames: []string{ServerName}, URIs: []*url.URL{u}}, f.bootstrapPrivate),
		"CAKey":     csr(&x509.CertificateRequest{DNSNames: []string{ServerName}, URIs: []*url.URL{u}}, ed25519.NewKeyFromSeed(f.issuer.seed[:])),
	}
	for name, d := range cases {
		t.Run(name, func(t *testing.T) {
			if _, e := f.issuer.IssueServer(d, b, f.now, time.Hour); e == nil {
				t.Fatal("accepted invalid CSR")
			}
		})
	}
	if _, e := f.issuer.IssueController(good, b, f.now, time.Hour); e == nil {
		t.Fatal("wrong issuer role")
	}
	if _, e := f.server.cert.WithKey(f.controller.key); e == nil {
		t.Fatal("wrong key")
	}
	leaf, e := x509.ParseCertificate(f.server.cert.DER())
	leaf = must(t, leaf, e)
	if leaf.IsCA || leaf.KeyUsage != x509.KeyUsageDigitalSignature || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatal("invalid leaf privileges")
	}
}
func TestValidity(t *testing.T) {
	f := setup(t)
	csr, e := f.server.key.CSR(serverBinding(t))
	csr = must(t, csr, e)
	for _, tc := range []struct {
		now  time.Time
		life time.Duration
	}{{time.Time{}, time.Hour}, {f.now, 0}, {f.now, MaxValidity + time.Second}, {f.now.Add(-time.Second), time.Hour}, {f.now.Add(23 * time.Hour), 2 * time.Hour}} {
		if _, e := f.issuer.IssueServer(csr, serverBinding(t), tc.now, tc.life); e == nil {
			t.Fatal("accepted invalid validity")
		}
	}
	if _, e := NewIssuer(time.Time{}, time.Hour, f.issuer.bootstrap); e == nil {
		t.Fatal("year zero CA")
	}
	if _, e := NewIssuer(f.now, time.Hour, BootstrapPublicKey{}); e == nil {
		t.Fatal("missing bootstrap public root")
	}
	leaf, e := x509.ParseCertificate(f.server.cert.DER())
	leaf = must(t, leaf, e)
	if !leaf.NotBefore.Equal(f.now) || leaf.NotAfter.Sub(leaf.NotBefore) != time.Hour {
		t.Fatal("wrong explicit issuance clock")
	}
}
func TestStrictTransport(t *testing.T) {
	f := setup(t)
	b := serverBinding(t)
	c, k, e := f.server.ExportPEM()
	if e != nil {
		t.Fatal(e)
	}
	id, e := ParseIdentityPEM(c, k, b)
	id = must(t, id, e)
	if id.key.PublicKey().Equal(f.server.key.PublicKey()) == false {
		t.Fatal("roundtrip")
	}
	if _, e := ParseRootPEM(f.issuer.Root().PEM()); e != nil {
		t.Fatal(e)
	}
	for name, mutate := range map[string]func([]byte) []byte{
		"duplicate": func(b []byte) []byte { return append(bytes.Clone(b), b...) }, "trailing": func(b []byte) []byte { return append(bytes.Clone(b), 'x') }, "whitespace": func(b []byte) []byte { return append(bytes.Clone(b), '\n') }, "prefix": func(b []byte) []byte { return append([]byte("junk\n"), b...) }, "unknown": func(b []byte) []byte { return bytes.ReplaceAll(b, []byte("CERTIFICATE"), []byte("UNKNOWN")) }, "oversize": func(b []byte) []byte { return bytes.Repeat(b, MaxPEMSize/len(b)+1) },
	} {
		t.Run(name, func(t *testing.T) {
			if _, e := ParseIdentityPEM(mutate(c), k, b); e == nil {
				t.Fatal("accepted certificate PEM")
			}
			if _, e := ParseRootPEM(mutate(f.issuer.Root().PEM())); e == nil {
				t.Fatal("accepted root PEM")
			}
		})
	}
	block, _ := pem.Decode(k)
	block.Headers = map[string]string{"X": "Y"}
	if _, e := ParseIdentityPEM(c, pem.EncodeToMemory(block), b); e == nil {
		t.Fatal("PEM headers")
	}
	for _, bad := range [][]byte{append(bytes.Clone(k), k...), append(bytes.Clone(k), 'x'), bytes.ReplaceAll(k, []byte("PRIVATE KEY"), []byte("EC PRIVATE KEY"))} {
		if _, e := ParseIdentityPEM(c, bad, b); e == nil {
			t.Fatal("bad key PEM")
		}
	}
	cd, kd, e := f.server.ExportDER()
	if e != nil {
		t.Fatal(e)
	}
	_, wrong, e := f.attachment.ExportDER()
	if e != nil {
		t.Fatal(e)
	}
	for _, bad := range [][]byte{wrong, append(bytes.Clone(kd), 0), nil, make([]byte, MaxDERSize+1)} {
		if _, e := ParseIdentityDER(cd, bad, b); e == nil {
			t.Fatal("bad key DER")
		}
	}
	if _, e := ParseIdentityDER(append(bytes.Clone(cd), 0), kd, b); e == nil {
		t.Fatal("trailing cert DER")
	}
	if _, e := ParseIdentityDER(cd, kd, controllerBinding(t)); e == nil {
		t.Fatal("binding mismatch")
	}
	clear(c)
	clear(k)
	clear(cd)
	clear(kd)
	if _, _, e := id.ExportDER(); e != nil {
		t.Fatal("import alias")
	}
}

// Real crypto/tls handshakes over an in-memory full-duplex transport. No listener,
// VM, fake tls.Config.Time, or synthetic verified-chain state is needed.
func handshake(sc, cc *tls.Config, check func(tls.ConnectionState) error) (tls.ConnectionState, tls.ConnectionState, error) {
	return handshakeClient(sc, func(raw net.Conn) *tls.Conn { return tls.Client(raw, cc) }, check)
}

func handshakeClient(sc *tls.Config, newClient func(net.Conn) *tls.Conn, check func(tls.ConnectionState) error) (tls.ConnectionState, tls.ConnectionState, error) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	left.SetDeadline(time.Now().Add(3 * time.Second))
	right.SetDeadline(time.Now().Add(3 * time.Second))
	server := tls.Server(left, sc)
	client := newClient(right)
	done := make(chan error, 1)
	go func() {
		e := server.Handshake()
		if e == nil && check != nil {
			e = check(server.ConnectionState())
		}
		if e == nil {
			_, e = server.Write([]byte{1})
		}
		left.Close()
		done <- e
	}()
	ce := client.Handshake()
	if ce == nil {
		var b [1]byte
		_, ce = io.ReadFull(client, b[:])
	}
	right.Close()
	se := <-done
	if ce == nil {
		ce = se
	}
	return server.ConnectionState(), client.ConnectionState(), ce
}
func configs(t *testing.T, f fixture, client Identity) (*tls.Config, *tls.Config) {
	t.Helper()
	sc, e := ServerTLSConfig(f.server, f.issuer.Root())
	sc = must(t, sc, e)
	// Package-internal config tests also exercise deliberately malformed controller
	// configurations; production callers can only obtain an opaque TLS connection.
	cc, e := clientTLSConfig(client, f.issuer.Root(), serverBinding(t), f.serverPin)
	cc = must(t, cc, e)
	return sc, cc
}
func TestNativeTLSRolesAndNoResume(t *testing.T) {
	f := setup(t)
	for _, id := range []Identity{f.controller, f.attachment} {
		sc, cc := configs(t, f, id)
		if sc.Time != nil || cc.Time != nil || sc.VerifyConnection != nil || sc.GetCertificate != nil || sc.GetConfigForClient != nil || !sc.SessionTicketsDisabled || !cc.SessionTicketsDisabled || cc.ClientSessionCache != nil || cc.InsecureSkipVerify {
			t.Fatal("unsafe TLS defaults")
		}
		if _, ok := sc.Certificates[0].PrivateKey.(ed25519.PrivateKey); !ok {
			t.Fatal("external signer")
		}
		for range 2 {
			ss, cs, e := handshake(sc, cc, func(s tls.ConnectionState) error {
				if id.cert.binding.role == ControllerRole {
					return VerifyController(s, f.issuer.Root(), id.cert.binding, f.controllerPin)
				}
				return VerifyAttachment(s, f.issuer.Root(), id.cert.binding, f.attachmentPin)
			})
			if e != nil {
				t.Fatal(e)
			}
			if ss.Version != tls.VersionTLS13 || cs.DidResume || ss.DidResume {
				t.Fatal("bad TLS version/resume")
			}
		}
	}
}
func TestNativeTLSRejectsScopeAndPin(t *testing.T) {
	f := setup(t)
	wrongStore, e := NewControllerBinding(StoreID(other), 7)
	wrongStore = must(t, wrongStore, e)
	wrongEpoch, e := NewControllerBinding(store, 8)
	wrongEpoch = must(t, wrongEpoch, e)
	for name, check := range map[string]func(tls.ConnectionState) error{
		"store": func(s tls.ConnectionState) error {
			return VerifyController(s, f.issuer.Root(), wrongStore, f.controllerPin)
		},
		"epoch": func(s tls.ConnectionState) error {
			return VerifyController(s, f.issuer.Root(), wrongEpoch, f.controllerPin)
		},
		"pin": func(s tls.ConnectionState) error {
			return VerifyController(s, f.issuer.Root(), controllerBinding(t), f.attachmentPin)
		},
		"role": func(s tls.ConnectionState) error {
			return VerifyAttachment(s, f.issuer.Root(), f.attachment.cert.binding, f.controllerPin)
		},
	} {
		t.Run(name, func(t *testing.T) {
			sc, cc := configs(t, f, f.controller)
			if _, _, e := handshake(sc, cc, check); e == nil {
				t.Fatal("scope accepted")
			}
		})
	}
	for name, mutate := range map[string]func(*AttachmentTuple){"attachment": func(a *AttachmentTuple) { a.Attachment = AttachmentID(store) }, "volume": func(a *AttachmentTuple) { a.Volume = VolumeID(store) }, "role": func(a *AttachmentTuple) { a.Role = PrepareRole; a.Prepare = PrepareID(other) }, "mode": func(a *AttachmentTuple) { a.Mode = ReadOnly }, "container": func(a *AttachmentTuple) { a.Container = ContainerID(strings.Repeat("b", 64)) }, "launch": func(a *AttachmentTuple) { a.Launch = LaunchID(store) }} {
		t.Run(name, func(t *testing.T) {
			a := tuple()
			mutate(&a)
			b := attachmentBinding(t, a)
			sc, cc := configs(t, f, f.attachment)
			if _, _, e := handshake(sc, cc, func(s tls.ConnectionState) error { return VerifyAttachment(s, f.issuer.Root(), b, f.attachmentPin) }); e == nil {
				t.Fatal("tuple accepted")
			}
		})
	}
	for name, mutate := range map[string]func(*tls.Config){"hostname": func(c *tls.Config) { c.ServerName = "wrong.invalid" }, "root": func(c *tls.Config) { c.RootCAs = x509.NewCertPool() }, "TLS12": func(c *tls.Config) { c.MinVersion = tls.VersionTLS12; c.MaxVersion = tls.VersionTLS12 }} {
		t.Run(name, func(t *testing.T) {
			sc, cc := configs(t, f, f.controller)
			mutate(cc)
			if _, _, e := handshake(sc, cc, nil); e == nil {
				t.Fatal("bad server accepted")
			}
		})
	}
}

// Malicious certificates are minted only by tests to exercise native TLS plus
// caller verification. Production issuance never accepts certificate templates.
func malicious(t *testing.T, f fixture, id Identity, mutate func(*x509.Certificate)) tls.Certificate {
	t.Helper()
	leaf, e := x509.ParseCertificate(id.cert.DER())
	leaf = must(t, leaf, e)
	ca, e := x509.ParseCertificate(f.issuer.Root().DER())
	ca = must(t, ca, e)
	mutate(leaf)
	der, e := x509.CreateCertificate(rand.Reader, leaf, ca, id.key.PublicKey(), ed25519.NewKeyFromSeed(f.issuer.seed[:]))
	der = must(t, der, e)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: id.key.private()}
}
func TestNativeTLSBadLeaves(t *testing.T) {
	f := setup(t)
	for name, mutate := range map[string]func(*x509.Certificate){"expired": func(c *x509.Certificate) { c.NotBefore = f.now.Add(-2 * time.Hour); c.NotAfter = f.now.Add(-time.Hour) }, "future": func(c *x509.Certificate) { c.NotBefore = f.now.Add(time.Hour); c.NotAfter = f.now.Add(2 * time.Hour) }, "clientEKUServer": func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }, "anyEKU": func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny} }, "bothEKU": func(c *x509.Certificate) {
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}, "CA": func(c *x509.Certificate) { c.IsCA = true }, "DNS": func(c *x509.Certificate) { c.DNSNames = []string{"wrong.invalid"} }, "noEKU": func(c *x509.Certificate) { c.ExtKeyUsage = nil }} {
		t.Run(name, func(t *testing.T) {
			sc, cc := configs(t, f, f.controller)
			sc.Certificates = []tls.Certificate{malicious(t, f, f.server, mutate)}
			if _, _, e := handshake(sc, cc, nil); e == nil {
				t.Fatal("bad server leaf accepted")
			}
		})
	}
	for name, mutate := range map[string]func(*x509.Certificate){"serverEKUClient": func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} }, "clientAnyEKU": func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny} }, "clientExpired": func(c *x509.Certificate) { c.NotBefore = f.now.Add(-2 * time.Hour); c.NotAfter = f.now.Add(-time.Hour) }} {
		t.Run(name, func(t *testing.T) {
			sc, cc := configs(t, f, f.controller)
			cc.Certificates = []tls.Certificate{malicious(t, f, f.controller, mutate)}
			if _, _, e := handshake(sc, cc, func(s tls.ConnectionState) error {
				return VerifyController(s, f.issuer.Root(), controllerBinding(t), f.controllerPin)
			}); e == nil {
				t.Fatal("bad client leaf accepted")
			}
		})
	}
}
func TestConfigIsolationConcurrent(t *testing.T) {
	f := setup(t)
	sc, cc := configs(t, f, f.controller)
	otherS, otherC := configs(t, f, f.controller)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 1000 {
			otherS.Certificates[0].Certificate[0][0] ^= 1
			otherS.Certificates[0].PrivateKey.(ed25519.PrivateKey)[0] ^= 1
			otherS.Certificates[0].Leaf.DNSNames[0] = "mutated"
			otherC.ServerName = "mutated"
			otherC.RootCAs = x509.NewCertPool()
		}
	}()
	_, _, e := handshake(sc, cc, func(s tls.ConnectionState) error {
		return VerifyController(s, f.issuer.Root(), controllerBinding(t), f.controllerPin)
	})
	wg.Wait()
	if e != nil {
		t.Fatal(e)
	}
}
