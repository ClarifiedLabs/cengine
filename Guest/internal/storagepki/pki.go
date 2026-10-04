package storagepki

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net/url"
	"time"
)

const MaxValidity = 24 * time.Hour
const MaxDERSize = 16 << 10
const MaxPEMSize = 32 << 10

// Fingerprint is SHA-256 of DER SubjectPublicKeyInfo, as in storageauthority.
type Fingerprint [32]byte

func (f Fingerprint) String() string { return hex.EncodeToString(f[:]) }
func PublicKeyFingerprint(public ed25519.PublicKey) (Fingerprint, error) {
	if len(public) != ed25519.PublicKeySize {
		return Fingerprint{}, ErrInvalid
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return Fingerprint{}, err
	}
	return sha256.Sum256(der), nil
}

// BootstrapPublicKey contains ONLY the externally owned privileged helper's
// public root. There is intentionally no bootstrap private-key constructor,
// signing/grant API, or relationship between this root and the generated TLS CA.
type BootstrapPublicKey struct {
	public [32]byte
	valid  bool
}

func NewBootstrapPublicKey(public ed25519.PublicKey) (BootstrapPublicKey, error) {
	if len(public) != ed25519.PublicKeySize || bytes.Equal(public, make([]byte, 32)) {
		return BootstrapPublicKey{}, ErrInvalid
	}
	var b BootstrapPublicKey
	copy(b.public[:], public)
	b.valid = true
	return b, nil
}
func (b BootstrapPublicKey) PublicKey() ed25519.PublicKey {
	if !b.valid {
		return nil
	}
	return bytes.Clone(b.public[:])
}

// Key has no Sign/Public crypto.Signer methods and retains no external callbacks.
// Constructors always generate random, role-specific keys. Never log credentials.
type Key struct {
	seed  [32]byte
	role  Role
	valid bool
}

func (Key) String() string     { return "storagepki.Key[REDACTED]" }
func (k Key) GoString() string { return k.String() }
func newKey(role Role) (Key, error) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Key{}, err
	}
	var k Key
	copy(k.seed[:], private.Seed())
	k.role = role
	k.valid = true
	return k, nil
}
func NewServerKey() (Key, error)     { return newKey(ServerRole) }
func NewControllerKey() (Key, error) { return newKey(ControllerRole) }

// NewAttachmentKey is called in trusted guest init, once per attachment. Only its
// CSR/public key goes to the host bridge; the private key stays in that guest.
func NewAttachmentKey(role Role) (Key, error) {
	if role != PrepareRole && role != RuntimeRole {
		return Key{}, ErrInvalid
	}
	return newKey(role)
}
func (k Key) private() ed25519.PrivateKey { return ed25519.NewKeyFromSeed(k.seed[:]) }
func (k Key) PublicKey() ed25519.PublicKey {
	if !k.valid {
		return nil
	}
	return bytes.Clone(k.private()[32:])
}
func (k Key) Fingerprint() (Fingerprint, error) { return PublicKeyFingerprint(k.PublicKey()) }
func (k Key) CSR(b Binding) ([]byte, error) {
	if !k.valid || b.uri == "" || k.role != b.role {
		return nil, ErrInvalid
	}
	u, _ := url.Parse(b.uri)
	t := &x509.CertificateRequest{URIs: []*url.URL{u}}
	if b.role == ServerRole {
		t.DNSNames = []string{ServerName}
	}
	return x509.CreateCertificateRequest(rand.Reader, t, k.private())
}

// Root is an immutable TLS trust anchor, NOT the helper bootstrap public root.
type Root struct{ der string }

func (r Root) DER() []byte { return []byte(r.der) }
func (r Root) PEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: r.DER()})
}
func ParseRootDER(der []byte) (Root, error) {
	if len(der) == 0 || len(der) > MaxDERSize {
		return Root{}, ErrInvalid
	}
	c, err := x509.ParseCertificate(bytes.Clone(der))
	if err != nil {
		return Root{}, ErrInvalid
	}
	if _, ok := c.PublicKey.(ed25519.PublicKey); !ok || !c.IsCA || !c.BasicConstraintsValid || c.KeyUsage != x509.KeyUsageCertSign || !c.MaxPathLenZero || len(c.ExtKeyUsage) != 0 || len(c.UnknownExtKeyUsage) != 0 || len(c.UnhandledCriticalExtensions) != 0 || !bounded(c.NotBefore, c.NotAfter) || c.CheckSignatureFrom(c) != nil {
		return Root{}, ErrInvalid
	}
	return Root{string(der)}, nil
}
func ParseRootPEM(data []byte) (Root, error) {
	der, err := decodePEM(data, "CERTIFICATE")
	if err != nil {
		return Root{}, err
	}
	return ParseRootDER(der)
}

// Issuer owns only a short-lived TLS CA. It has no persistence, authority state,
// takeover signer, external crypto.Signer, or process-wide key reuse registry.
type Issuer struct {
	root      Root
	seed      [32]byte
	bootstrap BootstrapPublicKey
}

func (Issuer) String() string     { return "storagepki.Issuer[REDACTED]" }
func (i Issuer) GoString() string { return i.String() }
func (i Issuer) Root() Root       { return i.root }
func bounded(start, end time.Time) bool {
	return start.Year() >= 1970 && end.Year() <= 9999 && end.After(start) && end.Sub(start) <= MaxValidity
}
func validity(now time.Time, lifetime time.Duration) (time.Time, time.Time, error) {
	now = now.UTC().Truncate(time.Second)
	end := now.Add(lifetime).Truncate(time.Second)
	if lifetime < time.Second || lifetime > MaxValidity || !bounded(now, end) {
		return time.Time{}, time.Time{}, ErrInvalid
	}
	return now, end, nil
}
func serial() (*big.Int, error) {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err == nil {
		n.Add(n, big.NewInt(1))
	}
	return n, err
}
func NewIssuer(now time.Time, lifetime time.Duration, bootstrap BootstrapPublicKey) (Issuer, error) {
	if !bootstrap.valid {
		return Issuer{}, ErrInvalid
	}
	start, end, err := validity(now, lifetime)
	if err != nil {
		return Issuer{}, err
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Issuer{}, err
	}
	if bytes.Equal(public, bootstrap.public[:]) {
		return Issuer{}, ErrInvalid
	}
	sn, err := serial()
	if err != nil {
		return Issuer{}, err
	}
	t := &x509.Certificate{SerialNumber: sn, Subject: pkix.Name{CommonName: "cengine storage TLS CA"}, NotBefore: start, NotAfter: end, IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, t, t, public, private)
	if err != nil {
		return Issuer{}, err
	}
	var i Issuer
	i.root = Root{string(der)}
	copy(i.seed[:], private.Seed())
	i.bootstrap = bootstrap
	return i, nil
}

// Certificate is public DER plus a frozen expected binding, not authorization.
type Certificate struct {
	der     string
	binding Binding
}

func (c Certificate) DER() []byte { return []byte(c.der) }
func (c Certificate) PEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.DER()})
}
func (c Certificate) Binding() Binding { return c.binding }

// ParseCertificateDER imports the bridge's public-only response. It validates
// size and expected leaf scope, not chain/time trust; TLS still verifies those.
// Guest init then calls WithKey using its locally retained attachment key.
func ParseCertificateDER(der []byte, expected Binding) (Certificate, error) {
	if len(der) == 0 || len(der) > MaxDERSize {
		return Certificate{}, ErrInvalid
	}
	owned := string(der)
	leaf, err := x509.ParseCertificate([]byte(owned))
	if err != nil || leafProfile(leaf, expected) != nil {
		return Certificate{}, ErrInvalid
	}
	return Certificate{owned, expected}, nil
}
func ParseCertificatePEM(data []byte, expected Binding) (Certificate, error) {
	der, err := decodePEM(data, "CERTIFICATE")
	if err != nil {
		return Certificate{}, err
	}
	return ParseCertificateDER(der, expected)
}
func (i Issuer) IssueServer(csr []byte, expected Binding, now time.Time, lifetime time.Duration) (Certificate, error) {
	return i.issue(csr, expected, ServerRole, now, lifetime)
}
func (i Issuer) IssueController(csr []byte, expected Binding, now time.Time, lifetime time.Duration) (Certificate, error) {
	return i.issue(csr, expected, ControllerRole, now, lifetime)
}
func (i Issuer) IssueAttachment(csr []byte, expected Binding, now time.Time, lifetime time.Duration) (Certificate, error) {
	if expected.role != PrepareRole && expected.role != RuntimeRole {
		return Certificate{}, ErrInvalid
	}
	return i.issue(csr, expected, expected.role, now, lifetime)
}

var sanOID = asn1.ObjectIdentifier{2, 5, 29, 17}

func sanDER(b Binding) []byte {
	// SAN GeneralNames contains only the one URI and (server only) fixed DNS name.
	names := []asn1.RawValue{}
	if b.role == ServerRole {
		names = append(names, asn1.RawValue{Class: 2, Tag: 2, Bytes: []byte(ServerName)})
	}
	names = append(names, asn1.RawValue{Class: 2, Tag: 6, Bytes: []byte(b.uri)})
	der, _ := asn1.Marshal(names)
	return der
}
func exactSAN(extensions []pkix.Extension, b Binding) bool {
	count := 0
	for _, ext := range extensions {
		if ext.Id.Equal(sanOID) {
			count++
			if !bytes.Equal(ext.Value, sanDER(b)) {
				return false
			}
		}
	}
	return count == 1
}
func (i Issuer) issue(der []byte, b Binding, role Role, now time.Time, lifetime time.Duration) (Certificate, error) {
	if i.root.der == "" || b.uri == "" || b.role != role || len(der) == 0 || len(der) > MaxDERSize {
		return Certificate{}, ErrInvalid
	}
	csr, err := x509.ParseCertificateRequest(bytes.Clone(der))
	if err != nil || csr.CheckSignature() != nil || csr.SignatureAlgorithm != x509.PureEd25519 || len(csr.Attributes) != 1 || len(csr.Extensions) != 1 || !exactSAN(csr.Extensions, b) || len(csr.Subject.Names) != 0 {
		return Certificate{}, ErrInvalid
	}
	public, ok := csr.PublicKey.(ed25519.PublicKey)
	if !ok || bytes.Equal(public, i.bootstrap.public[:]) || !canonicalCSR(csr, public, b) {
		return Certificate{}, ErrInvalid
	}
	ca, err := x509.ParseCertificate(i.root.DER())
	if err != nil || bytes.Equal(public, ca.PublicKey.(ed25519.PublicKey)) {
		return Certificate{}, ErrInvalid
	}
	start, end, err := validity(now, lifetime)
	if err != nil || start.Before(ca.NotBefore) || end.After(ca.NotAfter) {
		return Certificate{}, ErrInvalid
	}
	sn, err := serial()
	if err != nil {
		return Certificate{}, err
	}
	eku := x509.ExtKeyUsageClientAuth
	if role == ServerRole {
		eku = x509.ExtKeyUsageServerAuth
	}
	t := &x509.Certificate{SerialNumber: sn, NotBefore: start, NotAfter: end, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{eku}, ExtraExtensions: []pkix.Extension{{Id: sanOID, Value: sanDER(b)}}}
	cert, err := x509.CreateCertificate(rand.Reader, t, ca, public, ed25519.NewKeyFromSeed(i.seed[:]))
	if err != nil {
		return Certificate{}, err
	}
	return Certificate{string(cert), b}, nil
}

func leafProfile(c *x509.Certificate, b Binding) error {
	if b.uri == "" {
		return ErrInvalid
	}
	if _, ok := c.PublicKey.(ed25519.PublicKey); !ok {
		return ErrInvalid
	}
	eku := x509.ExtKeyUsageClientAuth
	if b.role == ServerRole {
		eku = x509.ExtKeyUsageServerAuth
	}
	if c.IsCA || !c.BasicConstraintsValid || c.KeyUsage != x509.KeyUsageDigitalSignature || len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != eku || len(c.UnknownExtKeyUsage) != 0 || len(c.UnhandledCriticalExtensions) != 0 || !bounded(c.NotBefore, c.NotAfter) || !exactSAN(c.Extensions, b) {
		return ErrInvalid
	}
	return nil
}

// Identity owns value copies. Export methods intentionally expose private key
// material ONLY for a trusted private init channel, never environment/argv/logs.
type Identity struct {
	cert Certificate
	key  Key
}

func (Identity) String() string     { return "storagepki.Identity[REDACTED]" }
func (i Identity) GoString() string { return i.String() }
func (c Certificate) WithKey(k Key) (Identity, error) {
	leaf, err := x509.ParseCertificate(c.DER())
	if err != nil || !k.valid || k.role != c.binding.role || leafProfile(leaf, c.binding) != nil || !bytes.Equal(leaf.PublicKey.(ed25519.PublicKey), k.PublicKey()) {
		return Identity{}, ErrInvalid
	}
	return Identity{c, k}, nil
}
func (i Identity) Certificate() Certificate { return i.cert }
func (i Identity) ExportDER() (certificate, privateKey []byte, err error) {
	// Controller keys stay in their owner; only typed proof/CSR/TLS use is allowed.
	if i.key.role == ControllerRole {
		return nil, nil, ErrInvalid
	}
	if _, err = i.cert.WithKey(i.key); err != nil {
		return nil, nil, err
	}
	privateKey, err = x509.MarshalPKCS8PrivateKey(i.key.private())
	return i.cert.DER(), privateKey, err
}
func (i Identity) ExportPEM() (certificate, privateKey []byte, err error) {
	c, k, err := i.ExportDER()
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k}), nil
}
func ParseIdentityDER(certDER, keyDER []byte, expected Binding) (Identity, error) {
	if len(certDER) == 0 || len(certDER) > MaxDERSize || len(keyDER) == 0 || len(keyDER) > MaxDERSize {
		return Identity{}, ErrInvalid
	}
	parsed, err := x509.ParsePKCS8PrivateKey(bytes.Clone(keyDER))
	if err != nil {
		return Identity{}, ErrInvalid
	}
	private, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return Identity{}, ErrInvalid
	}
	canonical, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil || !bytes.Equal(canonical, keyDER) {
		return Identity{}, ErrInvalid
	}
	var k Key
	copy(k.seed[:], private.Seed())
	k.role = expected.role
	k.valid = true
	return (Certificate{string(certDER), expected}).WithKey(k)
}
func ParseIdentityPEM(certPEM, keyPEM []byte, expected Binding) (Identity, error) {
	c, err := decodePEM(certPEM, "CERTIFICATE")
	if err != nil {
		return Identity{}, err
	}
	k, err := decodePEM(keyPEM, "PRIVATE KEY")
	if err != nil {
		return Identity{}, err
	}
	return ParseIdentityDER(c, k, expected)
}
func decodePEM(data []byte, kind string) ([]byte, error) {
	if len(data) == 0 || len(data) > MaxPEMSize || !bytes.HasPrefix(data, []byte("-----BEGIN "+kind+"-----\n")) {
		return nil, ErrInvalid
	}
	b, rest := pem.Decode(data)
	if b == nil || b.Type != kind || len(b.Headers) != 0 || len(rest) != 0 || len(b.Bytes) > MaxDERSize {
		return nil, ErrInvalid
	}
	// Reject skipped malformed blocks, alternate whitespace, and trailing data.
	if !bytes.Equal(data, pem.EncodeToMemory(b)) {
		return nil, ErrInvalid
	}
	return bytes.Clone(b.Bytes), nil
}
