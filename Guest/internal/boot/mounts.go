//go:build linux

package boot

import (
	"errors"
	"fmt"
	"os"
	"golang.org/x/sys/unix"
)

func MountKernelFilesystems() error {
	values:=[]struct{source,target,kind,data string;flags uintptr}{
		{"devtmpfs","/dev","devtmpfs","mode=0755",unix.MS_NOSUID},
		{"proc","/proc","proc","",unix.MS_NOSUID|unix.MS_NOEXEC|unix.MS_NODEV},
		{"sysfs","/sys","sysfs","",unix.MS_NOSUID|unix.MS_NOEXEC|unix.MS_NODEV},
		{"tmpfs","/run","tmpfs","mode=0755",unix.MS_NOSUID|unix.MS_NODEV},
	}
	for _,value:=range values{if err:=os.MkdirAll(value.target,0755);err!=nil{return err};if err:=unix.Mount(value.source,value.target,value.kind,value.flags,value.data);err!=nil&&!errors.Is(err,unix.EBUSY){return fmt.Errorf("mount %s: %w",value.target,err)}}
	return nil
}

func MountVirtioFS(tag,target string)error{if err:=os.MkdirAll(target,0755);err!=nil{return err};if err:=unix.Mount(tag,target,"virtiofs",0,"");err!=nil&&!errors.Is(err,unix.EBUSY){return fmt.Errorf("mount virtiofs %s: %w",tag,err)};return nil}
