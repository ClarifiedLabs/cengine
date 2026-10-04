package storageauthority

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// A subprocess owns umask: never change the test runner's process-global mask
// while unrelated authority/TLS work may be running.
func TestVolumeCreateDefaultMetadata(t *testing.T) {
	masks := []string{"000", "027", "077"}
	if os.Geteuid() == 0 {
		masks = append(masks, "777")
	}
	for _, mask := range masks {
		t.Run(mask, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestVolumeCreateMetadataWorker$", "-test.count=1")
			command.Env = append(os.Environ(), "CENGINE_VOLUME_METADATA_UMASK="+mask, "GORACE=atexit_sleep_ms=0")
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("metadata worker: %v\n%s", err, output)
			}
		})
	}
}

func TestVolumeCreateMetadataWorker(t *testing.T) {
	text := os.Getenv("CENGINE_VOLUME_METADATA_UMASK")
	if text == "" {
		return
	}
	mask, err := strconv.ParseUint(text, 8, 9)
	must(t, err)
	f := newLifecycleWorkloadFixture(t, nil)
	request := createRequest(t, f, "defaults")
	var parent unix.Stat_t
	must(t, unix.Fstat(int(f.a.j.exports.Fd()), &parent))
	previous := unix.Umask(int(mask))
	defer unix.Umask(previous)
	created, err := f.a.CreateVolume(f.control, request)
	unix.Umask(previous) // restore before cleanup, assertions and helper IO
	must(t, err)
	var root unix.Stat_t
	must(t, unix.Fstat(int(f.a.roots[request.Volume].Fd()), &root))
	if root.Mode&07777 != 0755 || root.Uid != uint32(os.Geteuid()) || root.Gid != parent.Gid {
		t.Fatalf("fresh data root: mode=%#o uid=%d gid=%d; want 0755 creator uid=%d parent gid=%d", root.Mode&07777, root.Uid, root.Gid, os.Geteuid(), parent.Gid)
	}
	if created.Volume.Root != (RootIdentity{uint64(root.Dev), root.Ino}) || created.Phase != VolumeReady {
		t.Fatal("published root identity/phase changed", created)
	}
	for _, dir := range []*os.File{f.a.j.exports, f.a.j.dir} {
		var private unix.Stat_t
		must(t, unix.Fstat(int(dir.Fd()), &private))
		if private.Mode&07777 != 0700 {
			t.Fatalf("private directory mode changed: %#o", private.Mode&07777)
		}
	}
}

func TestVolumeCreateReplayAndOpenPreserveMetadata(t *testing.T) {
	f := newLifecycleWorkloadFixture(t, nil)
	request := createRequest(t, f, "existing-metadata")
	created, err := f.a.CreateVolume(f.control, request)
	must(t, err)
	path := filepath.Join(f.path, "volumes", request.Name)
	must(t, os.WriteFile(filepath.Join(path, "preserved"), []byte("existing data"), 0600))
	root := f.a.roots[request.Volume]
	if os.Geteuid() == 0 {
		// Linux root execution also proves replay never restores owner/group.
		must(t, unix.Fchown(int(root.Fd()), 10002, 20002))
	}
	must(t, unix.Fchmod(int(root.Fd()), 03710))
	stamp := time.Unix(1700000000, 0)
	must(t, os.Chtimes(path, stamp, stamp))
	before, err := os.Stat(path)
	must(t, err)
	var beforeRaw unix.Stat_t
	must(t, unix.Fstat(int(root.Fd()), &beforeRaw))
	check := func(where string) {
		t.Helper()
		after, err := os.Stat(path)
		must(t, err)
		var raw unix.Stat_t
		must(t, unix.Stat(path, &raw))
		if !os.SameFile(before, after) || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) || raw.Uid != beforeRaw.Uid || raw.Gid != beforeRaw.Gid || raw.Mode != beforeRaw.Mode {
			t.Fatalf("%s normalized existing root metadata", where)
		}
		data, err := os.ReadFile(filepath.Join(path, "preserved"))
		must(t, err)
		if string(data) != "existing data" {
			t.Fatal("existing data changed")
		}
	}
	again, err := f.a.CreateVolume(f.control, request)
	must(t, err)
	if again != created {
		t.Fatal("replay changed receipt")
	}
	check("live replay")
	must(t, f.a.Close())
	f.a, err = f.openCurrent()
	must(t, err)
	f.control = f.authControl(f.controllerKey, 1)
	check("Open")
	again, err = f.a.CreateVolume(f.control, request)
	must(t, err)
	if again != created {
		t.Fatal("reopened replay changed receipt")
	}
	check("reopened replay")
}

func TestVolumeCreateMetadataPrecedesDurableReady(t *testing.T) {
	f := newLifecycleWorkloadFixture(t, nil)
	request := createRequest(t, f, "publication")
	var stages []string
	f.a.j.afterStep = func(stage string) {
		if stage != "volume-root-mode" && stage != "volume-root-sync" && stage != "volume-create-parent-sync" {
			return
		}
		stages = append(stages, stage)
		if f.a.s.VolumeLifecycles[request.Volume].Phase != VolumeCreating || f.a.roots[request.Volume] != nil {
			t.Error("root admitted before metadata and durability completed")
		}
		var root unix.Stat_t
		if err := unix.Fstatat(int(f.a.j.exports.Fd()), request.Name, &root, unix.AT_SYMLINK_NOFOLLOW); err != nil || root.Mode&07777 != 0755 {
			t.Errorf("%s before default mode: mode=%#o err=%v", stage, root.Mode&07777, err)
		}
	}
	created, err := f.a.CreateVolume(f.control, request)
	must(t, err)
	if fmt.Sprint(stages) != "[volume-root-mode volume-root-sync volume-create-parent-sync]" || created.Phase != VolumeReady {
		t.Fatal("metadata/durability publication order", stages, created.Phase)
	}
}
