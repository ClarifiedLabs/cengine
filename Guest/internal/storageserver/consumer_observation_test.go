package storageserver

import (
	"context"
	cc "dev.cengine/guest/internal/consumercompat"
	pc "dev.cengine/guest/internal/preparecompat"
	"strings"
	"sync"
	"testing"
	"time"
)

func recorderArm(t *testing.T) cc.Arm {
	launch := string(id(t))
	epoch := string(id(t))
	store := string(id(t))
	return cc.Arm{Version: cc.Version, Profile: cc.Profile, RequestID: string(id(t)), ArmDigest: strings.Repeat("a", 64), OperationUUID: string(id(t)), CaseName: cc.CrossE, OriginalBootBinding: cc.BootBinding{ShimLaunchUUID: launch, GuestBootNonce: string(id(t))}, Original: cc.Original{Epoch: string(id(t)), Binding: cc.RuntimeBinding{Store: store, Volume: string(id(t)), Attachment: string(id(t)), Container: strings.Repeat("b", 64), Launch: launch, Key: strings.Repeat("c", 64), Role: "runtime", Mode: "read-write"}}, OriginalLeafSHA256: strings.Repeat("d", 64), WorkerScope: cc.WorkerScope{StoreUUID: store, ServiceEpoch: epoch, WorkerUUID: string(id(t))}}
}
func TestConsumerRecorderOneShotRace(t *testing.T) {
	o := NewConsumerObservation()
	defer o.Close()
	q := recorderArm(t)
	_, err := o.Arm(q)
	if pc.CurrentProfile() != pc.FullProfile {
		if err == nil {
			t.Fatal("ordinary arm enabled")
		}
		ctx := context.Background()
		if o.Context(ctx) != ctx {
			t.Fatal("ordinary context changed")
		}
		return
	}
	must(t, err)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := o.Context(context.Background())
			o.Finish(ctx, context.Canceled)
			_, _ = o.Query(q)
		}()
	}
	wg.Wait()
	status, err := o.Query(q)
	must(t, err)
	if status.SelectedCount != 1 || status.State != "failed" || status.Evidence != nil {
		t.Fatal(status)
	}
	if _, err = o.Arm(q); err == nil {
		t.Fatal("rearmed")
	}
	fresh := NewConsumerObservation()
	defer fresh.Close()
	if _, err = fresh.Query(q); err == nil {
		t.Fatal("old worker state transfer")
	}
}
func TestConsumerRecorderFixedTenSecondExpiry(t *testing.T) {
	if pc.CurrentProfile() != pc.FullProfile {
		return
	}
	o := NewConsumerObservation()
	defer o.Close()
	q := recorderArm(t)
	start := time.Now()
	_, err := o.Arm(q)
	must(t, err)
	time.Sleep(10*time.Second + 50*time.Millisecond)
	status, err := o.Query(q)
	must(t, err)
	if status.State != "failed" || status.Failure != "timeout" || status.SelectedCount != 0 || status.Evidence != nil {
		t.Fatal(status)
	}
	if time.Since(start) < 10*time.Second {
		t.Fatal("lease shortened")
	}
	if _, err = o.Arm(q); err == nil {
		t.Fatal("timeout rearmed")
	}
}

func TestConsumerRecorderFinalizeCannotCreateEvidence(t *testing.T) {
	o := NewConsumerObservation()
	defer o.Close()
	q := recorderArm(t)
	if _, err := o.Finalize(q); err == nil {
		t.Fatal("finalized unarmed")
	}
	_, err := o.Arm(q)
	if pc.CurrentProfile() != pc.FullProfile {
		if err == nil {
			t.Fatal("ordinary arm")
		}
		if _, err = o.Finalize(q); err == nil {
			t.Fatal("ordinary finalize")
		}
		return
	}
	must(t, err)
	if _, err = o.Finalize(q); err == nil {
		t.Fatal("finalized armed")
	}
	ctx := o.Context(context.Background())
	if _, err = o.Finalize(q); err == nil {
		t.Fatal("finalized claimed")
	}
	o.Finish(ctx, context.Canceled)
	if _, err = o.Finalize(q); err == nil {
		t.Fatal("finalized failed")
	}
}
