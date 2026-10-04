package storageboot

import (
	"crypto/ed25519"
	"os"
	"testing"

	a "dev.cengine/guest/internal/storageauthority"
	s "dev.cengine/guest/internal/storageservice"
)

// Exercises the production purpose gate, read-only authority census, private
// worker codec, real worker constructor, supervisor Ready and reconciliation.
// The syscall-level RO->RW transition is tested separately in disk; temporary
// directories here are NOT evidence of native Linux ext4 qualification.
func TestResumeAdmissionWorkerSupervisorVertical(t *testing.T) {
	for _, genesis := range []bool{false, true} {
		name := "empty"
		if genesis {
			name = "genesis"
		}
		t.Run(name, func(t *testing.T) {
			signer, cfg := resumeTestConfiguration(t)
			root, err := os.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			binding := lifecycleTestBinding()
			if genesis {
				initial := LifecycleConfiguration{Action: "initialize", RootPublicKey: cfg.RootPublicKey, Signed: a.SignedLifecycleGrant{Grant: cfg.Resume.Request.Original}, NowUnixSeconds: cfg.NowUnixSeconds, LifetimeSeconds: cfg.LifetimeSeconds}
				msg, err := a.LifecycleGrantSigningBytes(initial.Signed.Grant)
				if err != nil {
					t.Fatal(err)
				}
				initial.Signed.Signature = ed25519.Sign(signer, msg)
				service, err := lifecycleConstruct(root, binding, initial, func() error { return nil })
				if err != nil {
					t.Fatal(err)
				}
				if err := service.Close(); err != nil {
					t.Fatal(err)
				}
			}
			admissions := 0
			gate := &lifecycleResumeGate{probe: true, promote: func(c LifecycleConfiguration) error {
				admissions++
				return a.AdmitLifecycleResumeReadOnly(a.Config{Root: root, DeviceID: binding.Ext4UUID, BootstrapKey: c.RootPublicKey, Barrier: func(a.Binding, *os.File) error { t.Error("read-only census invoked barrier"); return a.ErrInvalid }}, *c.Resume)
			}}
			workers := &inProcessLifecycle{}
			started := false
			start := workers.starterWithResume(root, binding, func() error { t.Error("resume consumed fresh formatting permission"); return nil }, func(service *s.LifecycleService) (func() error, error) {
				if admissions != 1 {
					t.Error("worker started before admission")
				}
				started = true
				return func() error { return nil }, nil
			}, gate)
			supervisor, err := newLifecycleSupervisor(cfg, start)
			if supervisor != nil {
				defer func() { supervisor.close(); workers.wg.Wait() }()
			}
			if err != nil {
				t.Fatal(err)
			}
			if !started || admissions != 1 || supervisor.ready.ControllerEpoch != 2 || supervisor.ready.ControllerKey != string(cfg.Signed.Grant.NewKey) {
				t.Fatal("wrong actual worker ready")
			}
			want := uint64(1)
			if genesis {
				want = 2
			}
			if supervisor.ready.OpenRevision != want {
				t.Fatal("wrong publication revision")
			}
			query, code := supervisor.dispatch(lifecycleSupervisorCommand(supervisor.ready, "query"))
			if code != "" || query == nil || query.Ready == nil || query.Ready.ServiceEpoch != supervisor.ready.ServiceEpoch {
				t.Fatal("actual worker query", code)
			}
			command := lifecycleSupervisorCommand(supervisor.ready, "reconcile-controller")
			command.Signed = &cfg.Signed
			controller := a.Controller{Epoch: 2, Key: cfg.Signed.Grant.NewKey}
			command.Controller = &controller
			reply, code := supervisor.dispatch(command)
			if code != "" || reply == nil || reply.Ready == nil || reply.Ready.ControllerEpoch != 2 {
				t.Fatal("actual worker reconcile", code)
			}
		})
	}
}

func TestResumeConfigurationRejectsMixedAuthorization(t *testing.T) {
	_, resume := resumeTestConfiguration(t)
	initial, _ := lifecycleTestConfig(t)
	initial.Resume = resume.Resume
	if initial.validate() == nil {
		t.Fatal("initialize carries resume authorization")
	}
	resume.Cold = &a.SignedLifecycleColdOpen{}
	if resume.validate() == nil {
		t.Fatal("resume carries cold authorization")
	}
}
