//go:build cengine_lifecycle_integration

package storageauthority

// Test-only bounded pipe worker. This deliberately uses INTERNAL principal seams,
// not TLS, native process authentication, or a production/nonexporting keyholder.
import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

type lifecycleBridgeRequest struct {
	Command string                `json:"command"`
	Signed  *SignedLifecycleGrant `json:"signed,omitempty"`
	Grant   *LifecycleGrant       `json:"grant,omitempty"`
	Nonce   []byte                `json:"nonce,omitempty"`
	RootKey []byte                `json:"rootKey,omitempty"`
}

// Actual live authority metadata, not a native/TLS authentication claim.
type lifecycleBridgeScope struct {
	Identity     LifecycleIdentity `json:"identity"`
	ServiceEpoch ID                `json:"serviceEpoch"`
	BootstrapKey Fingerprint       `json:"bootstrapKey"`
	OpenRevision uint64            `json:"openRevision"`
}
type lifecycleBridgeReply struct {
	ServiceResult  *LifecycleServiceResult `json:"serviceResult,omitempty"`
	MetadataScope  *lifecycleBridgeScope   `json:"metadataScope,omitempty"`
	Error          string                  `json:"error,omitempty"`
	Receipt        *LifecycleReceipt       `json:"receipt,omitempty"`
	Epoch          uint64                  `json:"epoch"`
	Revision       uint64                  `json:"revision"`
	Bytes          int64                   `json:"bytes"`
	Files          int                     `json:"files"`
	Fence          bool                    `json:"fence"`
	AggregateBytes int64                   `json:"aggregateBytes"`
}

func TestLifecycleIntegrationBridge(t *testing.T) {
	if os.Getenv("CENGINE_LIFECYCLE_BRIDGE") != "unsigned-test-only-v1" {
		t.Fatal("private integration worker requires explicit test-mode gate")
	}
	if flag.Lookup("test.run").Value.String() != "^TestLifecycleIntegrationBridge$" {
		t.Fatal("exact helper selection required")
	}
	base := t.TempDir()
	var a *Authority
	var root *os.File
	var path string
	var rootKey []byte
	var completedBytes int64
	defer func() {
		if a != nil {
			a.Close()
		}
		if root != nil {
			root.Close()
		}
	}()
	scan := bufio.NewScanner(os.Stdin)
	scan.Buffer(make([]byte, 4096), 64*1024)
	out := json.NewEncoder(os.Stdout)
	count, stores := 0, 0
	for scan.Scan() {
		count++
		if count > 50000 {
			t.Fatal("request budget exceeded")
		}
		var req lifecycleBridgeRequest
		d := json.NewDecoder(bytes.NewReader(scan.Bytes()))
		d.DisallowUnknownFields()
		if err := d.Decode(&req); err != nil {
			t.Fatal(err)
		}
		if err := d.Decode(new(any)); err != io.EOF {
			t.Fatal("trailing input")
		}
		if req.Command == "quit" {
			return
		}
		reply := lifecycleBridgeReply{}
		err := func() error {
			if req.Command == "apply" {
				if req.Signed == nil {
					return ErrInvalid
				}
				g := req.Signed.Grant
				switch g.Operation {
				case LifecycleInitialize:
					if a != nil {
						if a.s.Lifecycle.Seal == nil {
							return ErrBlocked
						}
						if err := a.Close(); err != nil {
							return err
						}
						a = nil
						root.Close()
						root = nil
						err := filepath.WalkDir(filepath.Join(path, registryName), func(p string, e os.DirEntry, err error) error {
							if err != nil {
								return err
							}
							if !e.IsDir() {
								s, err := e.Info()
								if err != nil {
									return err
								}
								completedBytes += s.Size()
							}
							return nil
						})
						if err != nil {
							return err
						}
					}
					if stores >= 140 {
						return ErrLimit
					}
					stores++
					if rootKey == nil {
						rootKey = append([]byte(nil), req.RootKey...)
					}
					if !bytes.Equal(rootKey, req.RootKey) {
						return ErrUnauthorized
					}
					path = filepath.Join(base, fmt.Sprintf("store-%d", stores))
					if err := os.Mkdir(path, 0700); err != nil {
						return err
					}
					if err := os.Mkdir(filepath.Join(path, "volumes"), 0700); err != nil {
						return err
					}
					var err error
					root, err = os.Open(path)
					if err != nil {
						return err
					}
					// No volumes/attachments exist: the resource barrier must never be needed.
					a, err = InitializeLifecycle(Config{Root: root, DeviceID: "integration-test-device", BootstrapKey: ed25519.PublicKey(rootKey), Barrier: func(Binding, *os.File) error { return ErrBlocked }}, *req.Signed)
					return err
				case LifecycleTakeover:
					if a == nil {
						return ErrInvalid
					}
					_, err := a.TakeoverLifecycle(&SuccessorPrincipal{a, g.NewKey}, *req.Signed)
					return err
				case LifecycleRetire:
					if a == nil {
						return ErrInvalid
					}
					return a.RetireLifecycle(&ControllerPrincipal{a, a.s.Controller.Epoch, a.s.Controller.Key}, *req.Signed)
				}
				return ErrInvalid
			}
			if a == nil {
				return ErrInvalid
			}
			switch req.Command {
			case "metadataScope":
				if req.Grant == nil || *req.Grant != a.s.Lifecycle.Latest.Grant {
					return ErrUnauthorized
				}
				return a.control(&ControllerPrincipal{a, a.s.Controller.Epoch, a.s.Controller.Key})
			case "serviceResult":
				if req.Grant == nil {
					return ErrInvalid
				}
				got, err := a.LifecycleServiceResult(&ControllerPrincipal{a, a.s.Controller.Epoch, a.s.Controller.Key}, *req.Grant, req.Nonce)
				if err == nil {
					reply.ServiceResult = &got
				}
				return err
			case "receipt":
				if req.Grant == nil {
					return ErrInvalid
				}
				got, err := a.LifecycleResult(&ControllerPrincipal{a, a.s.Controller.Epoch, a.s.Controller.Key}, *req.Grant, req.Nonce)
				if err == nil {
					reply.Receipt = &got
				}
				return err
			case "fence":
				if _, err := a.Query(&ControllerPrincipal{a, a.s.Controller.Epoch, a.s.Controller.Key}); err == nil {
					return fmt.Errorf("terminal query admitted")
				}
				if _, err := os.Stat(filepath.Join(path, registryName, lifecycleFenceName)); err != nil {
					return err
				}
				reply.Fence = true
				return nil
			default:
				return ErrInvalid
			}
		}()
		if err != nil {
			reply.Error = err.Error()
		}
		if a != nil {
			reply.MetadataScope = &lifecycleBridgeScope{a.s.Lifecycle.Identity, a.Epoch(), a.s.Bootstrap, a.s.Lifecycle.OpenRevision}
			reply.Epoch, reply.Revision = a.s.Controller.Epoch, a.s.Revision
			err = filepath.WalkDir(filepath.Join(path, registryName), func(p string, e os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if !e.IsDir() {
					s, err := e.Info()
					if err != nil {
						return err
					}
					reply.Bytes += s.Size()
					reply.Files++
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		}
		reply.AggregateBytes = completedBytes + reply.Bytes
		if err := out.Encode(reply); err != nil {
			t.Fatal(err)
		}
	}
	if err := scan.Err(); err != nil {
		t.Fatal(err)
	}
	t.Fatal("worker input closed without quit")
}
