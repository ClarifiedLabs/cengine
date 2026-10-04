package storageboot

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	a "dev.cengine/guest/internal/storageauthority"
	p "dev.cengine/guest/internal/storagepki"
)

// lifecycleTestSignChange signs with the test ROOT (seed 7s); invalid shapes are
// still signed over domain||JSON so shape rejection is exercised, not signature.
func lifecycleTestSignChange(t testing.TB, r p.LifecycleServiceChangeRequest) *p.SignedLifecycleServiceChange {
	t.Helper()
	msg, err := p.LifecycleServiceChangeSigningBytes(r)
	if err != nil {
		body, e := json.Marshal(r)
		if e != nil {
			t.Fatal(e)
		}
		msg = append([]byte("cengine.storageauthority.lifecycle-service-change.v2\x00"), body...)
	}
	root := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	return &p.SignedLifecycleServiceChange{Request: r, Signature: ed25519.Sign(root, msg)}
}

func lifecycleTestReopen(t *testing.T, cfg LifecycleConfiguration, ready *LifecycleReady) *p.SignedLifecycleServiceChange {
	t.Helper()
	digest := sha256.Sum256(ready.TLSRootDER)
	request := &p.LifecycleServiceChangeRequest{OperationID: "99999999-9999-4999-8999-999999999999", Predecessor: p.LifecycleServiceState{
		Grant: cfg.Signed.Grant, Context: p.LifecycleServiceContext{ServiceEpoch: ready.ServiceEpoch, ControllerEpoch: ready.ControllerEpoch, ControllerKey: ready.ControllerKey}, OpenRevision: ready.OpenRevision,
		Boot: p.LifecycleBootTrustFields{Identity: ready.Identity, ServiceEpoch: ready.ServiceEpoch, TLSRootSHA256: hex.EncodeToString(digest[:]), ServerSPKI: ready.ServerSPKI, BootstrapKey: ready.BootstrapKey},
	}}
	if err := request.Validate(); err != nil {
		t.Fatal(err)
	}
	return lifecycleTestSignChange(t, *request)
}

func lifecycleBootDisk(t *testing.T, root string) map[string]string {
	t.Helper()
	result := map[string]string{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			result[relative] = "directory"
			return nil
		}
		body, err := os.ReadFile(path)
		if err == nil {
			result[relative] = string(body)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestLifecycleBootExactReopenConsumesPredecessorOnce(t *testing.T) {
	root, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	cfg, _ := lifecycleTestConfig(t)
	service, err := lifecycleConstruct(root, lifecycleTestBinding(), cfg, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	ready, err := lifecyclePublicReady(service, "ffffffff-ffff-4fff-9fff-ffffffffffff")
	if err != nil {
		t.Fatal(err)
	}
	if err = service.Close(); err != nil {
		t.Fatal(err)
	}
	cfg.Action = "open"
	cfg.Reopen = lifecycleTestReopen(t, cfg, ready)
	before := lifecycleBootDisk(t, root.Name())
	for name, mutate := range map[string]func(*LifecycleConfiguration){
		"missing":          func(c *LifecycleConfiguration) { c.Reopen = nil },
		"action":           func(c *LifecycleConfiguration) { c.Action = "bogus" },
		"initialize-extra": func(c *LifecycleConfiguration) { c.Action = "initialize" },
		"grant-id": func(c *LifecycleConfiguration) {
			c.Reopen.Request.Predecessor.Grant.ID = a.ID(lifecycleTestBinding().ShimLaunchUUID)
		},
		"identity": func(c *LifecycleConfiguration) {
			c.Reopen.Request.Predecessor.Grant.Identity.Generation++
			c.Reopen.Request.Predecessor.Boot.Identity = c.Reopen.Request.Predecessor.Grant.Identity
		},
		"controller": func(c *LifecycleConfiguration) { c.Reopen.Request.Predecessor.Context.ControllerEpoch++ },
		"key": func(c *LifecycleConfiguration) {
			c.Reopen.Request.Predecessor.Context.ControllerKey = strings.Repeat("b", 64)
		},
		"stale": func(c *LifecycleConfiguration) {
			c.Reopen.Request.Predecessor.Context.ServiceEpoch = lifecycleTestBinding().ShimLaunchUUID
			c.Reopen.Request.Predecessor.Boot.ServiceEpoch = c.Reopen.Request.Predecessor.Context.ServiceEpoch
		},
		"root": func(c *LifecycleConfiguration) {
			c.Reopen.Request.Predecessor.Boot.BootstrapKey = strings.Repeat("b", 64)
		},
		"zero-anchor":   func(c *LifecycleConfiguration) { c.Reopen.Request.Predecessor.OpenRevision = 0 },
		"future-anchor": func(c *LifecycleConfiguration) { c.Reopen.Request.Predecessor.OpenRevision++ },
		"max-anchor":    func(c *LifecycleConfiguration) { c.Reopen.Request.Predecessor.OpenRevision = ^uint64(0) },
		// Valid shape, unauthorized: never re-signed below.
		"sig-forged": func(c *LifecycleConfiguration) { c.Reopen.Signature[0] ^= 1 },
		"sig-absent": func(c *LifecycleConfiguration) { c.Reopen.Signature = nil },
		"sig-other-root": func(c *LifecycleConfiguration) {
			msg, _ := p.LifecycleServiceChangeSigningBytes(c.Reopen.Request)
			c.Reopen.Signature = ed25519.Sign(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, 32)), msg)
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := cfg
			bad.Reopen = cfg.Reopen.Clone()
			mutate(&bad)
			if bad.Reopen != nil && !strings.HasPrefix(name, "sig-") {
				bad.Reopen = lifecycleTestSignChange(t, bad.Reopen.Request)
			}
			got, err := lifecycleConstruct(root, lifecycleTestBinding(), bad, nil)
			if got != nil {
				got.Close()
			}
			if err == nil {
				t.Fatal("accepted mismatch")
			}
			if !reflect.DeepEqual(before, lifecycleBootDisk(t, root.Name())) {
				t.Fatal("rejection mutated disk/E")
			}
		})
	}
	operation := cfg.Reopen.Request.OperationID
	service, err = lifecycleConstruct(root, lifecycleTestBinding(), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	after, err := lifecyclePublicReady(service, ready.WorkerUUID)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := service.Scope()
	if err != nil {
		t.Fatal(err)
	}
	if after.ServiceEpoch == ready.ServiceEpoch || after.Revision != ready.Revision+1 || after.OpenRevision != after.Revision || meta.CurrentGrant != cfg.Signed.Grant || after.ControllerEpoch != ready.ControllerEpoch || after.ControllerKey != ready.ControllerKey || cfg.Reopen.Request.OperationID != operation {
		t.Fatal("reopen changed ownership/operation or failed to advance E/anchor")
	}
	if err = service.Close(); err != nil {
		t.Fatal(err)
	}
	before = lifecycleBootDisk(t, root.Name())
	got, err := lifecycleConstruct(root, lifecycleTestBinding(), cfg, nil)
	if got != nil {
		got.Close()
	}
	if err == nil || !reflect.DeepEqual(before, lifecycleBootDisk(t, root.Name())) {
		t.Fatal("replayed predecessor mutated disk/E", err)
	}
	// Retain the exact live E/C/key/ROOT and signature, changing only its anchor.
	// A stale positive anchor must fail under the journal flock, not consume E.
	cfg.Reopen = lifecycleTestReopen(t, cfg, after)
	wrongAnchor := *cfg.Reopen
	wrongAnchor.Request.Predecessor.OpenRevision = ready.OpenRevision
	bad := cfg
	bad.Reopen = lifecycleTestSignChange(t, wrongAnchor.Request)
	got, err = lifecycleConstruct(root, lifecycleTestBinding(), bad, nil)
	if got != nil {
		got.Close()
	}
	if err == nil || !reflect.DeepEqual(before, lifecycleBootDisk(t, root.Name())) {
		t.Fatal("stale anchor with correct signed identity/E/C/key mutated disk", err)
	}
	service, err = lifecycleConstruct(root, lifecycleTestBinding(), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	next, err := lifecyclePublicReady(service, after.WorkerUUID)
	if err != nil {
		t.Fatal(err)
	}
	if next.ServiceEpoch == after.ServiceEpoch || next.OpenRevision != after.Revision+1 || cfg.Reopen.Request.OperationID != operation {
		t.Fatal("failed anchor candidate consumed E or replaced operation")
	}
	if err = service.Close(); err != nil {
		t.Fatal(err)
	}
	before = lifecycleBootDisk(t, root.Name())
	got, err = lifecycleConstruct(root, lifecycleTestBinding(), cfg, nil)
	if got != nil {
		got.Close()
	}
	if err == nil || !reflect.DeepEqual(before, lifecycleBootDisk(t, root.Name())) {
		t.Fatal("correct anchor was consumed more than once", err)
	}
}

func TestLifecycleBootDirectConfigurationRefusesBeforeVolumes(t *testing.T) {
	raw, err := os.ReadFile(lifecycleFixturePath)
	if err != nil {
		t.Fatal(err)
	}
	var vectors []string
	if err = json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	frame, err := DecodeLifecycleFrame([]byte(vectors[5]))
	if err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"identity", "root", "signature", "action", "time", "extra"} {
		t.Run(fault, func(t *testing.T) {
			root, err := os.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			cfg := *frame.Configuration
			signingKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
			switch fault {
			case "identity":
				cfg.Signed.Grant.Identity.Generation++
			case "root":
				signingKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, 32))
				cfg.RootPublicKey = signingKey.Public().(ed25519.PublicKey)
			case "action":
				cfg.Action = "invalid"
			case "time":
				cfg.NowUnixSeconds = 0
			case "extra":
				cfg.Action = "initialize"
			}
			message, err := a.LifecycleGrantSigningBytes(cfg.Signed.Grant)
			if err != nil {
				t.Fatal(err)
			}
			cfg.Signed.Signature = ed25519.Sign(signingKey, message)
			if fault == "signature" {
				cfg.Action = "initialize"
				cfg.Reopen = nil
				cfg.Signed.Signature[0] ^= 1
			}
			before := lifecycleBootDisk(t, root.Name())
			got, err := lifecycleConstruct(root, lifecycleTestBinding(), cfg, func() error { t.Fatal("invalid config reached fresh callback"); return nil })
			if got != nil {
				got.Close()
			}
			if err == nil || !reflect.DeepEqual(before, lifecycleBootDisk(t, root.Name())) {
				t.Fatal("invalid signed configuration mutated fresh root", err)
			}
		})
	}
}

func TestLifecycleBootReopenClosedFields(t *testing.T) {
	raw, err := os.ReadFile(lifecycleFixturePath)
	if err != nil {
		t.Fatal(err)
	}
	var vectors []string
	if err = json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, index := range []int{1, 2, 5} {
		var body map[string]any
		dec := json.NewDecoder(strings.NewReader(vectors[index]))
		dec.UseNumber()
		if err = dec.Decode(&body); err != nil {
			t.Fatal(err)
		}
		field := "reopen"
		nested := "configuration"
		if index == 2 {
			field = "open_revision"
			nested = "ready"
		}
		fields := body[nested].(map[string]any)
		original, present := fields[field]
		mutations := []any{nil, "missing", "extra"}
		if index == 2 {
			mutations = append(mutations, json.Number("0"), json.Number("2"))
		}
		for _, value := range mutations {
			if present {
				fields[field] = original
			} else {
				delete(fields, field)
			}
			delete(fields, "unknown")
			switch value {
			case "missing":
				if !present {
					continue
				}
				delete(fields, field)
			case "extra":
				fields["unknown"] = true
			default:
				fields[field] = value
			}
			bad, err := lifecycleCanonical(body)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = DecodeLifecycleFrame(bad); err == nil {
				t.Fatalf("accepted %s %v", field, value)
			}
		}
	}
}
