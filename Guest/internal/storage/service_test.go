//go:build linux

package storage

import (
	"os"
	"path/filepath"
	"testing"
	"golang.org/x/sys/unix"
)

func TestRemoveDirectoryContentsDoesNotFollowSymlinks(t *testing.T) {
	root:=t.TempDir();outside:=t.TempDir();if err:=os.WriteFile(filepath.Join(outside,"keep"),[]byte("safe"),0644);err!=nil{t.Fatal(err)};if err:=os.Mkdir(filepath.Join(root,"nested"),0755);err!=nil{t.Fatal(err)};if err:=os.WriteFile(filepath.Join(root,"nested/file"),[]byte("remove"),0644);err!=nil{t.Fatal(err)};if err:=os.Symlink(outside,filepath.Join(root,"link"));err!=nil{t.Fatal(err)}
	fd,err:=unix.Open(root,unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC,0);if err!=nil{t.Fatal(err)};defer unix.Close(fd);if err:=removeDirectoryContents(fd);err!=nil{t.Fatal(err)};entries,err:=os.ReadDir(root);if err!=nil{t.Fatal(err)};if len(entries)!=0{t.Fatalf("directory is not empty: %v",entries)};if data,err:=os.ReadFile(filepath.Join(outside,"keep"));err!=nil||string(data)!="safe"{t.Fatalf("symlink target changed: %q %v",data,err)}
}
