//go:build linux

package storageboot

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDataFailureConsoleRefusesRegularFile(t *testing.T) {
	file, err := os.Create(filepath.Join(t.TempDir(), "not-console"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	writeDataFailureConsoleFD(int(file.Fd()), []byte("must not write"))
	info, err := file.Stat()
	if err != nil || info.Size() != 0 {
		t.Fatal("console diagnostic wrote to a regular file")
	}
}
