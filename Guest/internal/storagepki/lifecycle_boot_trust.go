package storagepki

import a "dev.cengine/guest/internal/storageauthority"

// LifecycleBootTrustFields is value-only, never proof of ROOT authorization.
// TLSRootSHA256 hashes the exact TLS CA DER; BootstrapKey hashes ROOT's SPKI.
type LifecycleBootTrustFields struct {
	Identity      a.LifecycleIdentity `json:"identity"`
	ServiceEpoch  string              `json:"service_epoch"`
	TLSRootSHA256 string              `json:"tls_root_sha256"`
	ServerSPKI    string              `json:"server_spki"`
	BootstrapKey  string              `json:"bootstrap_key"`
}

func (f LifecycleBootTrustFields) Validate() error {
	if f.Identity.Validate() != nil || !uuid(f.ServiceEpoch) || !container(f.TLSRootSHA256) || !container(f.ServerSPKI) || !container(f.BootstrapKey) {
		return ErrInvalid
	}
	return nil
}

// Frozen and comparable; no caller-owned storage is retained.
type LifecycleBootTrust struct {
	fields    LifecycleBootTrustFields
	canonical string
}

func NewLifecycleBootTrust(f LifecycleBootTrustFields) (LifecycleBootTrust, error) {
	if err := f.Validate(); err != nil {
		return LifecycleBootTrust{}, err
	}
	b, err := lifecycleChildCanonical(f)
	if err != nil {
		return LifecycleBootTrust{}, err
	}
	return LifecycleBootTrust{fields: f, canonical: string(b)}, nil
}
func (b LifecycleBootTrust) Fields() LifecycleBootTrustFields { return b.fields }
func (b LifecycleBootTrust) Canonical() []byte                { return []byte(b.canonical) }
func (b LifecycleBootTrust) MatchesGrant(g a.LifecycleGrant) bool {
	return b.canonical != "" && g.Validate() == nil && b.fields.Identity == g.Identity
}
func cloneLifecycleBootTrust(f *LifecycleBootTrustFields) *LifecycleBootTrustFields {
	if f == nil {
		return nil
	}
	copy := *f
	return &copy
}
