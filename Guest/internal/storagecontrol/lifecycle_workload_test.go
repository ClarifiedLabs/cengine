package storagecontrol

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	a "dev.cengine/guest/internal/storageauthority"
	p "dev.cengine/guest/internal/storagepki"
	"golang.org/x/sys/unix"
)

func workloadConfigs(f *lifecycleFixture) (PKILifecycleWorkloadServerConfig, PKILifecycleWorkloadClientConfig) {
	controller := a.Controller{Epoch: 1, Key: f.initial.Grant.NewKey}
	return PKILifecycleWorkloadServerConfig{Identity: f.sc.Identity, ClientRoot: f.sc.ClientRoot, LifecycleIdentity: f.initial.Grant.Identity, ServiceEpoch: f.sc.ServiceEpoch, CurrentController: controller},
		PKILifecycleWorkloadClientConfig{Identity: f.cc.Identity, ServerRoot: f.cc.ServerRoot, ServerKey: f.cc.ServerKey, LifecycleIdentity: f.initial.Grant.Identity, ServiceEpoch: f.sc.ServiceEpoch, CurrentController: controller}
}

// Include the whole durable store, not just public lifecycle metadata: a refused
// wire operation must not rewrite private journal tables or filesystem evidence.
func workloadStoreCensus(t *testing.T, root string) map[string]any {
	t.Helper()
	out := map[string]any{}
	must(t, filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		var st unix.Stat_t
		if err := unix.Lstat(path, &st); err != nil {
			return err
		}
		var data []byte
		if entry.Type().IsRegular() {
			data, err = os.ReadFile(path)
			if err != nil {
				return err
			}
		} else if entry.Type()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			data = []byte(target)
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		out[relative] = struct {
			Mode, UID, GID       uint32
			Device, Inode, Links uint64
			Size                 int64
			Data                 string
		}{uint32(st.Mode), st.Uid, st.Gid, uint64(st.Dev), uint64(st.Ino), uint64(st.Nlink), st.Size, string(data)}
		return nil
	}))
	return out
}

func TestLifecycleWorkloadTLSQueryAndTakeoverRefusal(t *testing.T) {
	f := newLifecycleTLSFixture(t)
	sc, cc := workloadConfigs(f)
	s, err := NewPKILifecycleWorkloadServer(f.authority, sc)
	must(t, err)
	raw, worker := servePKI(t, s)
	client, err := NewPKILifecycleWorkloadClient(context.Background(), raw, cc)
	must(t, err)
	defer client.Close()
	created := call(t, client, Request{CreateVolume: &a.CreateVolumeRequest{Operation: id(t), Store: cc.LifecycleIdentity.Store, Volume: id(t), Name: "workload"}})
	if created.VolumeReceipt.Schema != a.SchemaVersion {
		t.Fatal("receipt schema changed")
	}
	r := call(t, client, Request{Query: &Empty{}})
	if r.Snapshot.Schema != a.LifecycleSchemaVersion || r.LifecycleIdentity == nil || *r.LifecycleIdentity != cc.LifecycleIdentity || r.Snapshot.Controller != cc.CurrentController || r.Snapshot.Epoch != cc.ServiceEpoch || r.Snapshot.Volumes[created.VolumeReceipt.Volume.ID] != created.VolumeReceipt.Volume {
		t.Fatal("wrong bound snapshot")
	}
	// Local historical wire shape is a negative probe, not an authority API.
	grant := struct {
		ID            a.ID          `json:"id"`
		Store         a.ID          `json:"store"`
		ExpectedEpoch uint64        `json:"expected_epoch"`
		NewKey        a.Fingerprint `json:"new_key"`
	}{f.takeover.Grant.ID, cc.LifecycleIdentity.Store, cc.CurrentController.Epoch, f.takeover.Grant.NewKey}
	encoded, err := json.Marshal(grant)
	must(t, err)
	signing := append([]byte("cengine.storageauthority.takeover.v1\x00"), encoded...)
	signature := ed25519.Sign(f.bootstrap, signing)
	if !ed25519.Verify(f.bootstrap.Public().(ed25519.PublicKey), signing, signature) {
		t.Fatal("negative probe is not correctly bootstrap-signed")
	}
	probe, err := json.Marshal(struct {
		Grant     json.RawMessage `json:"grant"`
		Signature []byte          `json:"signature"`
	}{encoded, signature})
	must(t, err)
	before, err := f.authority.LifecycleMetadata()
	must(t, err)
	durable := workloadStoreCensus(t, f.rootPath)
	assertUnchanged := func() {
		t.Helper()
		after, err := f.authority.LifecycleMetadata()
		must(t, err)
		snapshot := call(t, client, Request{Query: &Empty{}})
		if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(r.Snapshot, snapshot.Snapshot) ||
			!reflect.DeepEqual(durable, workloadStoreCensus(t, f.rootPath)) {
			t.Fatal("refused takeover changed authority, workload state, or durable store")
		}
	}
	_, err = client.Call(context.Background(), Request{Takeover: probe})
	remote(t, err, Unauthorized)
	assertUnchanged()
	// Bypass the client role guard: a workload connection still cannot invoke
	// the old takeover operation. The dedicated lifecycle endpoint owns it.
	must(t, writeFrame(client.conn, Request{ID: client.id + 1, Takeover: probe}, 4096, &budget{}))
	var denied Response
	must(t, readFrame(client.conn, &denied, 4096, &budget{}))
	if !reflect.DeepEqual(denied, Response{ID: client.id + 1, Error: Unauthorized}) {
		t.Fatal("v1 takeover admitted", denied)
	}
	// The bypass consumed one wire ID without going through Client.Call.
	client.id = denied.ID
	assertUnchanged()
	client.Close()
	worker.wait(t)
}

func TestLifecycleWorkloadServerConstructorRequiresRealMatchingMetadata(t *testing.T) {
	f := newLifecycleTLSFixture(t)
	sc, _ := workloadConfigs(f)
	for _, kind := range []string{"generation", "binding", "store", "service", "epoch", "key"} {
		t.Run(kind, func(t *testing.T) {
			c := sc
			switch kind {
			case "generation":
				c.LifecycleIdentity.Generation++
			case "binding":
				c.LifecycleIdentity.Binding = f.initial.Grant.NewKey
			case "store":
				c.LifecycleIdentity.Store = id(t)
			case "service":
				c.ServiceEpoch = id(t)
			case "epoch":
				c.CurrentController.Epoch++
			case "key":
				c.CurrentController.Key = f.takeover.Grant.NewKey
			}
			if _, err := NewPKILifecycleWorkloadServer(f.authority, c); !errors.Is(err, ErrConfiguration) {
				t.Fatal("mismatched metadata accepted", err)
			}
		})
	}
	other := newLifecycleTLSFixture(t)
	if _, err := NewPKILifecycleWorkloadServer(other.authority, sc); !errors.Is(err, ErrConfiguration) {
		t.Fatal("different lifecycle authority accepted", err)
	}
}

func TestLifecycleWorkloadTLSHelloClosedPolicy(t *testing.T) {
	for _, kind := range []string{"v2", "missing", "generation", "binding", "store", "service", "controller", "successor", "unknown", "null"} {
		t.Run(kind, func(t *testing.T) {
			f := newLifecycleTLSFixture(t)
			sc, cc := workloadConfigs(f)
			s, err := NewPKILifecycleWorkloadServer(f.authority, sc)
			must(t, err)
			raw, worker := servePKI(t, s)
			server, err := p.NewServerBinding(p.StoreID(cc.LifecycleIdentity.Store), p.ServiceEpoch(cc.ServiceEpoch))
			must(t, err)
			conn, err := p.NewControllerTLSClient(raw, cc.Identity, cc.ServerRoot, server, cc.ServerKey)
			must(t, err)
			must(t, conn.SetDeadline(time.Now().Add(3*time.Second)))
			must(t, conn.HandshakeContext(context.Background()))
			i := cc.LifecycleIdentity
			h := Hello{Version: LifecycleWorkloadVersion, Role: Controller, ControllerEpoch: 1, Store: i.Store, ServiceEpoch: cc.ServiceEpoch, LifecycleIdentity: &i}
			switch kind {
			case "v2":
				h.Version = 2
				h.LifecycleIdentity = nil
			case "missing":
				h.LifecycleIdentity = nil
			case "generation":
				i.Generation++
			case "binding":
				i.Binding = f.initial.Grant.NewKey
			case "store":
				i.Store = id(t)
			case "service":
				h.ServiceEpoch = id(t)
			case "controller":
				h.ControllerEpoch++
			case "successor":
				h.Role = Successor
				h.ControllerEpoch = 0
			}
			if kind == "unknown" || kind == "null" {
				b, err := json.Marshal(h)
				must(t, err)
				var m map[string]any
				must(t, json.Unmarshal(b, &m))
				if kind == "unknown" {
					m["extra"] = 1
				} else {
					m["lifecycle_identity"] = nil
				}
				must(t, writeFrame(conn, m, 4096, &budget{}))
			} else {
				must(t, writeFrame(conn, h, 4096, &budget{}))
			}
			var reply HelloReply
			if err = readFrame(conn, &reply, 4096, &budget{}); err == nil && reply.Error == "" {
				t.Fatal("bad hello admitted")
			}
			raw.Close()
			if worker.wait(t) == nil {
				t.Fatal("bad hello accepted")
			}
		})
	}
}

func TestLifecycleWorkloadTLSClientRejectsWrongQueryAndHello(t *testing.T) {
	for _, kind := range []string{"schema3", "missing", "generation", "binding", "service", "store", "revision", "controller-key", "controller-epoch", "hello-version", "hello-missing", "hello-binding", "hello-generation", "hello-service"} {
		t.Run(kind, func(t *testing.T) {
			f := newLifecycleTLSFixture(t)
			sc, cc := workloadConfigs(f)
			cfg, err := p.ServerTLSConfig(sc.Identity, sc.ClientRoot)
			must(t, err)
			left, right := tcpPair(t)
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer left.Close()
				conn := tls.Server(left, cfg)
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				var h Hello
				if readFrame(conn, &h, 4096, &budget{}) != nil {
					return
				}
				reply := HelloReply{Version: h.Version, Store: h.Store, ServiceEpoch: h.ServiceEpoch, LifecycleIdentity: h.LifecycleIdentity}
				switch kind {
				case "hello-version":
					reply.Version = 2
				case "hello-missing":
					reply.LifecycleIdentity = nil
				case "hello-binding":
					reply.LifecycleIdentity.Binding = f.initial.Grant.NewKey
				case "hello-generation":
					reply.LifecycleIdentity.Generation++
				case "hello-service":
					reply.ServiceEpoch = id(t)
				}
				if writeFrame(conn, reply, 4096, &budget{}) != nil {
					return
				}
				var q Request
				if readFrame(conn, &q, 4096, &budget{}) != nil {
					return
				}
				snap := a.Snapshot{Schema: a.LifecycleSchemaVersion, Revision: 1, Store: a.Store{ID: h.Store}, Epoch: h.ServiceEpoch, Controller: cc.CurrentController, Volumes: map[a.ID]a.Volume{}, VolumeLifecycles: map[a.ID]a.VolumeLifecycle{}, Attachments: map[a.ID]a.Attachment{}, Prepares: map[a.ID]a.Prepare{}}
				r := Response{ID: q.ID, Snapshot: &snap, LifecycleIdentity: h.LifecycleIdentity}
				switch kind {
				case "schema3":
					snap.Schema = a.SchemaVersion
				case "missing":
					r.LifecycleIdentity = nil
				case "generation":
					r.LifecycleIdentity.Generation++
				case "binding":
					r.LifecycleIdentity.Binding = f.initial.Grant.NewKey
				case "service":
					snap.Epoch = id(t)
				case "store":
					snap.Store.ID = id(t)
				case "revision":
					snap.Revision = 0
				case "controller-key":
					snap.Controller.Key = f.takeover.Grant.NewKey
				case "controller-epoch":
					snap.Controller.Epoch++
				}
				writeFrame(conn, r, 1<<20, &budget{})
			}()
			client, err := NewPKILifecycleWorkloadClient(context.Background(), right, cc)
			if err == nil {
				_, err = client.Call(context.Background(), Request{Query: &Empty{}})
				client.Close()
			}
			if !errors.Is(err, ErrProtocol) {
				t.Fatal("bad reply accepted or wrong failure", err)
			}
			<-done
		})
	}
}
