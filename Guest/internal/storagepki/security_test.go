package storagepki

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"testing"
)

func TestVerifierRequiresActualHandshake(t *testing.T) {
	f := setup(t)
	sc, cc := configs(t, f, f.controller)
	ss, cs, e := handshake(sc, cc, nil)
	if e != nil {
		t.Fatal(e)
	}
	if e := VerifyServer(cs, f.issuer.Root(), serverBinding(t), f.serverPin); e != nil {
		t.Fatal(e)
	}
	for name, mutate := range map[string]func(*tls.ConnectionState){
		"incomplete":   func(s *tls.ConnectionState) { s.HandshakeComplete = false },
		"resumed":      func(s *tls.ConnectionState) { s.DidResume = true },
		"unverified":   func(s *tls.ConnectionState) { s.VerifiedChains = nil },
		"nilLeaf":      func(s *tls.ConnectionState) { s.PeerCertificates = []*x509.Certificate{nil} },
		"nilChainLeaf": func(s *tls.ConnectionState) { s.VerifiedChains = [][]*x509.Certificate{{nil}} },
		"multipleCerts": func(s *tls.ConnectionState) {
			s.PeerCertificates = append([]*x509.Certificate{s.PeerCertificates[0]}, s.PeerCertificates...)
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := ss
			mutate(&s)
			if e := VerifyController(s, f.issuer.Root(), controllerBinding(t), f.controllerPin); e == nil {
				t.Fatal("invalid state accepted")
			}
		})
	}
}
func TestControllerCredentialsCannotEscapeTLSOrExport(t *testing.T) {
	f := setup(t)
	for name, export := range map[string]func() ([]byte, []byte, error){"DER": f.controller.ExportDER, "PEM": f.controller.ExportPEM} {
		t.Run(name, func(t *testing.T) {
			cert, key, err := export()
			if !errors.Is(err, ErrInvalid) || cert != nil || key != nil {
				t.Fatal("controller credential export was not rejected")
			}
		})
	}
	if cfg, err := ClientTLSConfig(f.controller, f.issuer.Root(), serverBinding(t), f.serverPin); !errors.Is(err, ErrInvalid) || cfg != nil {
		t.Fatal("controller TLS config exposed its private key or signer")
	}
	if cfg, err := ServerTLSConfig(f.controller, f.issuer.Root()); !errors.Is(err, ErrInvalid) || cfg != nil {
		t.Fatal("controller credential escaped via server TLS config")
	}
}

func TestControllerTLSConstructorRejectsInvalidInputs(t *testing.T) {
	f := setup(t)
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	for name, tc := range map[string]struct {
		raw      net.Conn
		identity Identity
		root     Root
		server   Binding
		pin      Fingerprint
	}{
		"nil transport":       {nil, f.controller, f.issuer.Root(), serverBinding(t), f.serverPin},
		"TLS transport":       {tls.Client(right, &tls.Config{}), f.controller, f.issuer.Root(), serverBinding(t), f.serverPin},
		"zero identity":       {right, Identity{}, f.issuer.Root(), serverBinding(t), f.serverPin},
		"server identity":     {right, f.server, f.issuer.Root(), serverBinding(t), f.serverPin},
		"attachment identity": {right, f.attachment, f.issuer.Root(), serverBinding(t), f.serverPin},
		"zero root":           {right, f.controller, Root{}, serverBinding(t), f.serverPin},
		"zero pin":            {right, f.controller, f.issuer.Root(), serverBinding(t), Fingerprint{}},
		"client binding":      {right, f.controller, f.issuer.Root(), controllerBinding(t), f.serverPin},
	} {
		t.Run(name, func(t *testing.T) {
			if conn, err := NewControllerTLSClient(tc.raw, tc.identity, tc.root, tc.server, tc.pin); !errors.Is(err, ErrInvalid) || conn != nil {
				t.Fatal("invalid controller TLS input accepted")
			}
		})
	}
}

func TestZeroValuesAndBootstrapCopies(t *testing.T) {
	f := setup(t)
	if _, e := ServerTLSConfig(Identity{}, f.issuer.Root()); e == nil {
		t.Fatal("zero identity")
	}
	if _, e := ClientTLSConfig(f.attachment, Root{}, serverBinding(t), f.serverPin); e == nil {
		t.Fatal("zero root")
	}
	if _, e := ClientTLSConfig(f.attachment, f.issuer.Root(), serverBinding(t), Fingerprint{}); e == nil {
		t.Fatal("zero pin")
	}
	if _, e := NewBootstrapPublicKey(make(ed25519.PublicKey, 32)); e == nil {
		t.Fatal("zero bootstrap")
	}
	pub := f.issuer.bootstrap.PublicKey()
	original := append(ed25519.PublicKey(nil), pub...)
	boot, e := NewBootstrapPublicKey(pub)
	if e != nil {
		t.Fatal(e)
	}
	clear(pub)
	out := boot.PublicKey()
	clear(out)
	if !boot.PublicKey().Equal(original) {
		t.Fatal("bootstrap alias")
	}
	if _, _, e := (Identity{}).ExportDER(); e == nil {
		t.Fatal("zero export")
	}
}
