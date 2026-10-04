package storagecontrol

import "crypto/x509"

// DER is the sole trust policy input: CertPool.Equal cannot detect or preserve
// AddCertWithConstraint callbacks. Never accept a caller-owned pool at all.
func validLeaf(cert *x509.Certificate, use x509.ExtKeyUsage) bool {
	return cert != nil && !cert.IsCA && cert.KeyUsage == x509.KeyUsageDigitalSignature && len(cert.ExtKeyUsage) == 1 && cert.ExtKeyUsage[0] == use && len(cert.UnknownExtKeyUsage) == 0
}
