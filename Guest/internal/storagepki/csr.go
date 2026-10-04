package storagepki

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
)

var extensionRequestOID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}

type requestAttribute struct {
	ID     asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}
type requestInfo struct {
	Version    int
	Subject    asn1.RawValue
	PublicKey  asn1.RawValue
	Attributes []asn1.RawValue `asn1:"tag:0"`
}

// x509's parsed Attributes omits some signed raw attributes and only reads the
// first extensionRequest value. Compare the ENTIRE signed request info with the
// one allowed canonical encoding, rather than trusting that lossy projection.
func canonicalCSR(csr *x509.CertificateRequest, public ed25519.PublicKey, b Binding) bool {
	spki, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return false
	}
	extensions, err := asn1.Marshal([]pkix.Extension{{Id: sanOID, Value: sanDER(b)}})
	if err != nil {
		return false
	}
	attribute, err := asn1.Marshal(requestAttribute{extensionRequestOID, []asn1.RawValue{{FullBytes: extensions}}})
	if err != nil {
		return false
	}
	expected, err := asn1.Marshal(requestInfo{0, asn1.RawValue{FullBytes: []byte{0x30, 0}}, asn1.RawValue{FullBytes: spki}, []asn1.RawValue{{FullBytes: attribute}}})
	return err == nil && bytes.Equal(csr.RawTBSCertificateRequest, expected)
}
