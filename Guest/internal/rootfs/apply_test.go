//go:build linux

package rootfs

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestApplyLayerResolvesForwardHardlinks(t *testing.T) {
	root := t.TempDir(); var archive bytes.Buffer; writer := tar.NewWriter(&archive); modified := time.Unix(1_700_000_000, 123)
	if err := writer.WriteHeader(&tar.Header{Name:"link",Linkname:"file",Typeflag:tar.TypeLink,Mode:0644,ModTime:modified});err!=nil{t.Fatal(err)}
	contents:=[]byte("payload");if err:=writer.WriteHeader(&tar.Header{Name:"file",Typeflag:tar.TypeReg,Mode:0644,Size:int64(len(contents)),ModTime:modified});err!=nil{t.Fatal(err)};if _,err:=writer.Write(contents);err!=nil{t.Fatal(err)};if err:=writer.Close();err!=nil{t.Fatal(err)}
	if err:=applyLayer(root,&archive);err!=nil{t.Fatal(err)}
	file,err:=os.Stat(filepath.Join(root,"file"));if err!=nil{t.Fatal(err)};link,err:=os.Stat(filepath.Join(root,"link"));if err!=nil{t.Fatal(err)};if !os.SameFile(file,link){t.Fatal("forward hard link did not preserve inode identity")};if data,err:=os.ReadFile(filepath.Join(root,"link"));err!=nil||string(data)!="payload"{t.Fatalf("unexpected content %q: %v",data,err)}
}

func TestApplyLayerRejectsSymlinkParentTraversal(t *testing.T) {
	root:=t.TempDir();outside:=t.TempDir();var archive bytes.Buffer;writer:=tar.NewWriter(&archive)
	if err:=writer.WriteHeader(&tar.Header{Name:"escape",Linkname:outside,Typeflag:tar.TypeSymlink,Mode:0777});err!=nil{t.Fatal(err)};data:=[]byte("bad");if err:=writer.WriteHeader(&tar.Header{Name:"escape/payload",Typeflag:tar.TypeReg,Mode:0644,Size:int64(len(data))});err!=nil{t.Fatal(err)};_,_=writer.Write(data);_ = writer.Close()
	if err:=applyLayer(root,&archive);err==nil{t.Fatal("symlink parent traversal was accepted")};if _,err:=os.Stat(filepath.Join(outside,"payload"));!os.IsNotExist(err){t.Fatalf("payload escaped root: %v",err)}
}
