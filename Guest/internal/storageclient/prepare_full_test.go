//go:build cengine_prepare_full_compat && !cengine_prepare_compat && !cengine_prepare_early_compat

package storageclient

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"

	pc "dev.cengine/guest/internal/preparecompat"
	a "dev.cengine/guest/internal/storageauthority"
	w "dev.cengine/guest/internal/storagewire"
)

func fullClientWitness(t *testing.T, cfg *Config) *pc.Witness {
	t.Helper()
	cfg.Authority.Binding.Role = a.PrepareRole
	cfg.Authority.Binding.Prepare = testID('6')
	b := cfg.Authority.Binding
	sum := sha256.Sum256(cfg.TLSConfig.Certificates[0].Certificate[0])
	arm := pc.Arm{Version: 3, Profile: pc.FullProfile, RequestID: string(testID('7')), CaseName: "data-partial-frame", TargetAttachment: string(b.Attachment), Binding: pc.BootBinding{ShimLaunchUUID: string(b.Launch), GuestBootNonce: string(testID('8'))}, Scope: pc.Scope{Intent: string(testID('9')), Store: string(b.Store), ServiceEpoch: string(cfg.Authority.Epoch), ControllerEpoch: 1, ControllerKey: strings.Repeat("b", 64), Container: string(b.Container), ContainerInstance: string(testID('8')), Launch: string(b.Launch), Prepare: string(b.Prepare), SpecificationDigest: strings.Repeat("c", 64)}, Mounts: []pc.MountBinding{{Index: 0, Volume: string(b.Volume), Destination: "/data", Mode: "read-write"}}, Slots: []pc.Slot{{Volume: string(b.Volume), Attachment: string(b.Attachment), Role: "prepare", Mode: "read-write"}, {Volume: string(b.Volume), Attachment: string(testID('0')), Role: "runtime", Mode: "read-write"}}, Credentials: []pc.Credential{{Attachment: string(b.Attachment), Key: string(b.Key), CertificateSHA256: hex.EncodeToString(sum[:])}}}
	witness, err := pc.NewWitness(arm)
	if err != nil {
		t.Fatal(err)
	}
	if err := witness.AcceptPrepare(77); err != nil {
		t.Fatal(err)
	}
	cfg.PrepareCompatibility = witness
	return witness
}
func TestFullActualTLSA3FiveBytesAndObserverJoin(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "written", true: "write-failure"}[fail], func(t *testing.T) {
			var witness *pc.Witness
			received := make(chan []byte, 1)
			closed := make(chan struct{})
			client := fixture(t, func(cfg *Config) { witness = fullClientWitness(t, cfg) }, func(conn *tls.Conn) {
				var req w.Request
				if err := w.ReadFrame(conn, &req); err != nil {
					t.Error(err)
					return
				}
				if req.Sequence != 1 || req.Body.Operation() != w.OpOpenDir {
					t.Error("prior DATA request")
				}
				if err := w.WriteFrame(conn, &w.Reply{Sequence: req.Sequence, Op: w.OpOpenDir, Body: w.OpenDirReply{Opened: w.Opened{Handle: 100}}}); err != nil {
					t.Error(err)
					return
				}
				prefix := make([]byte, 5)
				if _, err := io.ReadFull(conn, prefix); err != nil {
					t.Error(err)
					return
				}
				received <- prefix
				rest, _ := io.ReadAll(conn)
				if len(rest) != 0 {
					t.Error("complete DATA frame or synthesized result")
				}
				close(closed)
			})
			opened, err := client.Do(caller(client), 0, w.OpenDirRequest{Node: 99})
			if err != nil {
				t.Fatal(err)
			}
			grant, err := client.Handle(opened.Handle)
			if err != nil {
				t.Fatal(err)
			}
			body := w.PrepareRequest{Node: 99, Handle: grant.Handle, Action: w.BeginCopy}
			returned := make(chan error, 1)
			go func() { _, err := client.Do(caller(client), 0, body); returned <- err }()
			prefix := <-received
			var encoded bytes.Buffer
			authCaller := caller(client).caller
			request := w.Request{Sequence: 2, Auth: w.Auth{Kind: w.CallerAuth, Caller: &authCaller}, Body: body}
			if w.WriteFrame(&encoded, &request) != nil || !bytes.Equal(prefix, encoded.Bytes()[:5]) {
				t.Fatal("not actual serialized request prefix")
			}
			observation := <-witness.EarlyObservations()
			if observation.Version != 3 || observation.Profile != pc.FullProfile || observation.RequestSequence != 2 || observation.DataBytesWritten != 5 || pc.ValidateEarlyObservation(observation) != nil {
				t.Fatal("A3 counters/profile")
			}
			select {
			case <-returned:
				t.Fatal("returned before observer write")
			default:
			}
			select {
			case <-closed:
				t.Fatal("DATA closed before observation")
			default:
			}
			var writeErr error
			if fail {
				writeErr = errors.New("observation transport")
			}
			if !witness.ObservationWritten(writeErr) {
				t.Fatal("observer ack")
			}
			if err := <-returned; err == nil {
				t.Fatal("partial frame succeeded")
			}
			<-closed
			waitTerminal(t, client)
			if witness.NormalObservationWritten() {
				t.Fatal("A3 promoted to normal")
			}
		})
	}
}
func TestFullDATARequiresActualTupleAndLeaf(t *testing.T) {
	cfg, _ := tlsPair(t)
	witness := fullClientWitness(t, &cfg)
	der := cfg.TLSConfig.Certificates[0].Certificate[0]
	if witness.ValidateDataAuthority(cfg.Authority, der) != nil {
		t.Fatal("actual TLS authority rejected")
	}
	for _, mutate := range []func(*a.DataHello){func(h *a.DataHello) { h.Epoch = testID('9') }, func(h *a.DataHello) { h.Binding.Store = testID('9') }, func(h *a.DataHello) { h.Binding.Volume = testID('9') }, func(h *a.DataHello) { h.Binding.Prepare = testID('9') }, func(h *a.DataHello) { h.Binding.Attachment = testID('9') }, func(h *a.DataHello) { h.Binding.Launch = testID('9') }, func(h *a.DataHello) { h.Binding.Container = a.ContainerID(strings.Repeat("9", 64)) }, func(h *a.DataHello) { h.Binding.Key = a.Fingerprint(strings.Repeat("9", 64)) }, func(h *a.DataHello) { h.Binding.Mode = a.ReadOnly }, func(h *a.DataHello) { h.Binding.Role = a.RuntimeRole }} {
		bad := cfg.Authority
		mutate(&bad)
		if witness.ValidateDataAuthority(bad, der) == nil {
			t.Fatal("forged full tuple")
		}
	}
	if witness.ValidateDataAuthority(cfg.Authority, append([]byte{0}, der...)) == nil {
		t.Fatal("forged issued leaf")
	}
}
