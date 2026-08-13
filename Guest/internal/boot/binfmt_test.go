//go:build linux

package boot

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// unescapeHex decodes the \xHH escape sequences the binfmt_misc register
// parser understands, leaving all other bytes untouched.
func unescapeHex(t *testing.T, s string) []byte {
	t.Helper()
	var out []byte
	for i := 0; i < len(s); {
		if s[i] == '\\' {
			if i+3 >= len(s) || s[i+1] != 'x' {
				t.Fatalf("malformed escape at offset %d in %q", i, s)
			}
			value, err := strconv.ParseUint(s[i+2:i+4], 16, 8)
			if err != nil {
				t.Fatalf("malformed hex escape at offset %d in %q: %v", i, s, err)
			}
			out = append(out, byte(value))
			i += 4
			continue
		}
		out = append(out, s[i])
		i++
	}
	return out
}

func TestRosettaRegistrationEntryIsByteExact(t *testing.T) {
	entry := RosettaRegistrationEntry("/run/cengine/rosetta/rosetta")
	wantMagic := []byte{
		0x7f, 'E', 'L', 'F', // ELF signature
		0x02,                   // EI_CLASS: ELFCLASS64
		0x01,                   // EI_DATA: ELFDATA2LSB
		0x01,                   // EI_VERSION: EV_CURRENT
		0x00,                   // EI_OSABI: System V
		0x00, 0x00, 0x00, 0x00, // EI_ABIVERSION + padding
		0x00, 0x00, 0x00, 0x00,
		0x02, 0x00, // e_type: ET_EXEC
		0x3e, 0x00, // e_machine: EM_X86_64
	}
	wantMask := []byte{
		0xff, 0xff, 0xff, 0xff,
		0xff, 0xfe, 0xfe, 0x00,
		0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff,
		0xfe, 0xff, // e_type mask also accepts ET_DYN
		0xff, 0xff, // e_machine must be exactly EM_X86_64
	}
	fields := strings.Split(entry, ":")
	if len(fields) != 8 || fields[0] != "" || fields[1] != "rosetta" || fields[2] != "M" || fields[3] != "" {
		t.Fatalf("RosettaRegistrationEntry fields = %q", entry)
	}
	if got := unescapeHex(t, fields[4]); string(got) != string(wantMagic) {
		t.Fatalf("decoded magic = %x, want %x", got, wantMagic)
	}
	if got := unescapeHex(t, fields[5]); string(got) != string(wantMask) {
		t.Fatalf("decoded mask = %x, want %x", got, wantMask)
	}
	if fields[6] != "/run/cengine/rosetta/rosetta" {
		t.Fatalf("interpreter field = %q", fields[6])
	}
	// The binfmt_misc register parser treats the entry as a C string, so a
	// raw NUL byte would silently truncate the field it appears in.
	if strings.ContainsRune(entry, 0) {
		t.Fatalf("RosettaRegistrationEntry contains a raw NUL byte: %q", entry)
	}
	if !strings.HasSuffix(entry, ":OCF") {
		t.Fatalf("RosettaRegistrationEntry loses mandatory OCF flags: %q", entry)
	}
}

func TestRegisterBinfmtHandlerWritesExactEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "register")
	entry := RosettaRegistrationEntry("/run/cengine/rosetta/rosetta")
	if err := registerBinfmtHandler(path, entry); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != entry {
		t.Fatalf("register content = %q, want %q", content, entry)
	}
}

func TestRegisterBinfmtHandlerReportsMissingFilesystem(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "register")
	if err := registerBinfmtHandler(path, RosettaRegistrationEntry("/rosetta")); err == nil {
		t.Fatal("registerBinfmtHandler succeeded without a binfmt_misc filesystem")
	}
}
