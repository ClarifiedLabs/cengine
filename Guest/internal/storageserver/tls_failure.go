package storageserver

import a "dev.cengine/guest/internal/storageauthority"

// TLSFailurePrefixDomain separates the digest of raw client-to-server bytes
// from certificate hashes. Digest = SHA256(domain || exactly ByteCount bytes).
const TLSFailurePrefixDomain = "cengine/storageserver/tls-failure-read-prefix/v1\x00"

// TLSFailureSnapshot is public observation data, not authority or a probe result.
// It describes only a real failed TLS handshake, never a complete client flight.
// No certificate, ciphertext, exporter, or private key is retained here.
type TLSFailureSnapshot struct {
	Store                     a.ID
	ServiceEpoch              a.ID
	RejectedCertificateSHA256 [32]byte
	ByteCount                 uint64
	PrefixSHA256              [32]byte
}

// TLSFailureEvidence accepts only the package-private wrapper produced by Serve.
// A caller-authored error (including an As implementation) cannot mint evidence.
// Ordinary builds never produce this wrapper. The returned value is a copy.
func TLSFailureEvidence(err error) (TLSFailureSnapshot, bool) {
	if e, ok := err.(*tlsFailureError); ok && e != nil {
		return e.snapshot, true
	}
	return TLSFailureSnapshot{}, false
}

type helloFailureError struct {
	cause    error
	snapshot TLSFailureSnapshot
	hello    a.DataHello
}

func (e *helloFailureError) Error() string { return "storageserver: observed PKI Hello mismatch" }
func (e *helloFailureError) Unwrap() error { return e.cause }

type tlsFailureError struct {
	cause    error
	snapshot TLSFailureSnapshot
}

func (*tlsFailureError) Error() string      { return "storageserver: observed TLS client unknown authority" }
func (e *tlsFailureError) Unwrap() error    { return e.cause }
func (e *tlsFailureError) GoString() string { return e.Error() }
