package storagefuse

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// Test-only wall-budget calibration: the retained current-guest 30s run reached
// operation 327. Pinned corpus/completion and storage/drain deadlines are unchanged.
const (
	fsxChildArgument   = "--storagefuse-fsx-child-v1"
	fsxSHA256          = "d4293e6536e184abd383c258104765bbdec783faa7025cde93c797c97067a632"
	fsxBinaryBytes     = 780384
	fsxOutputLimit     = 1 << 20
	fsxDiagnosticAfter = 20 * time.Second
	fsxChildLimit      = 150 * time.Second
	fsxCompletion      = "All operations completed A-OK!\n"
)

func fsxChildSelected(args []string) bool {
	return len(args) == 2 && args[1] == fsxChildArgument
}

func fsxArgv() []string {
	return []string{"/fsx", "-d", "-S", "1", "-N", "1000", "-l", "4194304", "-o", "65536", "fsx-file"}
}

func fsxStaticARM64(raw []byte) error {
	f, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	defer f.Close()
	if f.Class != elf.ELFCLASS64 || f.Data != elf.ELFDATA2LSB || f.Machine != elf.EM_AARCH64 || f.Type != elf.ET_EXEC {
		return errors.New("fsx ELF profile")
	}
	load := false
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP || p.Type == elf.PT_DYNAMIC {
			return errors.New("fsx dynamic ELF")
		}
		if p.Type == elf.PT_LOAD {
			load = true
		}
	}
	if !load {
		return errors.New("fsx missing load segment")
	}
	return nil
}

func fsxVerifyBytes(raw []byte) error {
	if len(raw) != fsxBinaryBytes || fmt.Sprintf("%x", sha256.Sum256(raw)) != fsxSHA256 {
		return errors.New("fsx binary pin")
	}
	return fsxStaticARM64(raw)
}

// Drain every write even after the private capture fills. Never send fsx -d to
// the outer 128 KiB receipt, and never let output pressure block the workload.
// Overflow is a test failure, not permission to pass from a truncated marker.
type fsxCapture struct {
	mu       sync.Mutex
	data     []byte
	overflow bool
}

func (b *fsxCapture) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := min(len(p), fsxOutputLimit-len(b.data))
	b.data = append(b.data, p[:n]...)
	b.overflow = b.overflow || n != len(p)
	return len(p), nil
}

func (b *fsxCapture) snapshot() ([]byte, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.data...), b.overflow
}

// The pinned upstream source's main() loops numops times, closes its files, then
// prints this marker (fsx-linux.c:1339-1343). Skipped operations need not have a
// numbered -d line. Exact pinned argv -N 1000 + real exit 0 + this final line are
// the completion proof; counting debug records would reject legitimate skips.
func fsxOutputProof(raw []byte, overflow bool, exitErr error) error {
	if exitErr != nil || overflow || len(raw) > fsxOutputLimit ||
		!bytes.HasSuffix(raw, []byte(fsxCompletion)) ||
		bytes.Count(raw, []byte(fsxCompletion)) != 1 {
		return errors.New("fsx completion proof")
	}
	prefix := raw[:len(raw)-len(fsxCompletion)]
	if len(prefix) != 0 && prefix[len(prefix)-1] != '\n' {
		return errors.New("fsx completion line")
	}
	return nil
}

func TestNativeFsxContract(t *testing.T) {
	want := []string{"/fsx", "-d", "-S", "1", "-N", "1000", "-l", "4194304", "-o", "65536", "fsx-file"}
	if fmt.Sprint(fsxArgv()) != fmt.Sprint(want) || fsxChildLimit != 150*time.Second || fsxDiagnosticAfter != 20*time.Second {
		t.Fatal("fsx fixed workload changed")
	}
	for _, args := range [][]string{nil, {"test"}, {"test", "fsx"}, {"test", fsxChildArgument, "-N", "2"}, {"test", "-test.run=Fsx"}} {
		if fsxChildSelected(args) {
			t.Fatal("open child selector", args)
		}
	}
	if !fsxChildSelected([]string{"test", fsxChildArgument}) {
		t.Fatal("closed child selector")
	}
	for _, raw := range [][]byte{nil, make([]byte, fsxBinaryBytes-1), make([]byte, fsxBinaryBytes), make([]byte, fsxBinaryBytes+1)} {
		if fsxVerifyBytes(raw) == nil {
			t.Fatal("unpinned input accepted")
		}
	}
}

func TestNativeFsxStaticELF(t *testing.T) {
	raw := make([]byte, 120)
	copy(raw, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(raw[16:], uint16(elf.ET_EXEC))
	binary.LittleEndian.PutUint16(raw[18:], uint16(elf.EM_AARCH64))
	binary.LittleEndian.PutUint32(raw[20:], 1)
	binary.LittleEndian.PutUint64(raw[32:], 64)
	binary.LittleEndian.PutUint16(raw[52:], 64)
	binary.LittleEndian.PutUint16(raw[54:], 56)
	binary.LittleEndian.PutUint16(raw[56:], 1)
	binary.LittleEndian.PutUint32(raw[64:], uint32(elf.PT_LOAD))
	if err := fsxStaticARM64(raw); err != nil {
		t.Fatal(err)
	}
	for _, change := range []struct {
		offset int
		value  uint16
	}{{16, uint16(elf.ET_DYN)}, {18, uint16(elf.EM_X86_64)}} {
		bad := append([]byte(nil), raw...)
		binary.LittleEndian.PutUint16(bad[change.offset:], change.value)
		if fsxStaticARM64(bad) == nil {
			t.Fatal("wrong ELF profile accepted")
		}
	}
	for _, kind := range []elf.ProgType{elf.PT_INTERP, elf.PT_DYNAMIC, elf.PT_NULL} {
		binary.LittleEndian.PutUint32(raw[64:], uint32(kind))
		if fsxStaticARM64(raw) == nil {
			t.Fatal("unsafe ELF accepted", kind)
		}
	}
}

func TestNativeFsxOutputProof(t *testing.T) {
	// No numbered op 1000: skipped operations are legitimate in this corpus.
	good := []byte("000999 mapwrite\nskipping zero size read\n" + fsxCompletion)
	if err := fsxOutputProof(good, false, nil); err != nil {
		t.Fatal(err)
	}
	for _, raw := range [][]byte{nil, []byte("0001000 write\n"), []byte("prefix" + fsxCompletion), append(append([]byte(nil), good...), 'x'), []byte(fsxCompletion + fsxCompletion)} {
		if fsxOutputProof(raw, false, nil) == nil {
			t.Fatal("false completion accepted")
		}
	}
	if fsxOutputProof(good, true, nil) == nil || fsxOutputProof(good, false, errors.New("exit 1")) == nil {
		t.Fatal("output overrode failure")
	}
	b := &fsxCapture{}
	payload := bytes.Repeat([]byte("x"), fsxOutputLimit-1)
	b.Write(payload)
	b.Write([]byte("yz"))
	b.Write([]byte(fsxCompletion))
	raw, overflow := b.snapshot()
	if len(raw) != fsxOutputLimit || !overflow || raw[len(raw)-1] != 'y' || fsxOutputProof(raw, overflow, nil) == nil {
		t.Fatal("capture bound/proof lost")
	}
	// The full >64 KiB debug stream remains private and can still pass.
	b = &fsxCapture{}
	b.Write(bytes.Repeat([]byte("debug\n"), 20000))
	b.Write([]byte(fsxCompletion))
	raw, overflow = b.snapshot()
	if len(raw) <= nativeChildOutputLimit || fsxOutputProof(raw, overflow, nil) != nil {
		t.Fatal("full output lost")
	}
}
