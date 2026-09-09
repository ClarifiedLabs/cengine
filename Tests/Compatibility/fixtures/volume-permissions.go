// Secret-free Linux probe for RTM-053/054; built independently of Guest modules.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

const payload = "disposable-metadata-probe\n"

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func number(s string) int {
	n, err := strconv.ParseInt(s, 0, 32)
	must(err)
	return int(n)
}

func metadata(info os.FileInfo, uid, gid, mode int) {
	s := info.Sys().(*syscall.Stat_t)
	if int(s.Uid) != uid || int(s.Gid) != gid || int(s.Mode&07777) != mode {
		panic(fmt.Sprintf("%s: got %d:%d %#o; want %d:%d %#o", info.Name(), s.Uid, s.Gid, s.Mode, uid, gid, mode))
	}
}

func verify(path string, uid, gid int) {
	f, err := os.Open(path)
	must(err)
	info, err := f.Stat()
	must(err)
	metadata(info, uid, gid, 0600)
	must(f.Close())
	data, err := os.ReadFile(path)
	must(err)
	if string(data) != payload {
		panic("disposable content changed")
	}
}

func create(path string, uid, gid int) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	must(err)
	// Fstat the still-open descriptor before writing even disposable data.
	info, err := f.Stat()
	must(err)
	if !info.Mode().IsRegular() {
		panic("not a regular file")
	}
	metadata(info, uid, gid, 0600)
	_, err = f.WriteString(payload)
	must(err)
	must(f.Sync())
	must(f.Close())
	verify(path, uid, gid)
}

func denied(err error) {
	if !errors.Is(err, syscall.EACCES) && !errors.Is(err, syscall.EPERM) {
		panic(fmt.Sprintf("expected EACCES/EPERM, got %v", err))
	}
}

func main() {
	a := os.Args[1:]
	switch a[0] {
	case "serve":
		for {
			time.Sleep(time.Hour)
		}
	case "stat":
		info, err := os.Stat(a[1])
		must(err)
		s := info.Sys().(*syscall.Stat_t)
		must(json.NewEncoder(os.Stdout).Encode(map[string]uint32{"uid": s.Uid, "gid": s.Gid, "mode": uint32(s.Mode & 07777)}))
	case "configure":
		must(os.Chown(a[1], number(a[2]), number(a[3])))
		// Chown may clear special bits; chmod must follow it.
		must(syscall.Chmod(a[1], uint32(number(a[4]))))
	case "mkdir":
		must(os.Mkdir(a[1], 0777))
	case "create":
		create(a[1], number(a[2]), number(a[3]))
	case "verify":
		verify(a[1], number(a[2]), number(a[3]))
	case "absent":
		_, err := os.Lstat(a[1])
		if !errors.Is(err, os.ErrNotExist) {
			panic(fmt.Sprintf("expected absent: %v", err))
		}
	case "read-seed":
		data, err := os.ReadFile(a[1])
		must(err)
		if string(data) != "image-seed\n" {
			panic("image contents changed")
		}
	case "deny-create":
		f, err := os.OpenFile(a[1], os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if f != nil {
			f.Close()
		}
		denied(err)
	case "deny":
		_, err := os.ReadFile(a[1])
		denied(err)
		f, err := os.OpenFile(a[1], os.O_WRONLY, 0)
		if f != nil {
			f.Close()
		}
		denied(err)
		denied(os.Truncate(a[1], 0))
		denied(os.Chmod(a[1], 0666))
		denied(os.Chown(a[1], os.Geteuid(), os.Getegid()))
	case "deny-chown":
		denied(os.Chown(a[1], number(a[2]), -1))
		denied(os.Chown(a[1], -1, number(a[3])))
	case "group":
		gid := number(a[2])
		groups, err := os.Getgroups()
		must(err)
		found := false
		for _, group := range groups {
			found = found || group == gid
		}
		if !found || os.Getegid() == gid {
			panic("not a supplementary group")
		}
		create(filepath.Join(a[1], "group-file"), os.Geteuid(), gid)
		dir := filepath.Join(a[1], "group-dir")
		must(os.Mkdir(dir, 0700))
		info, err := os.Stat(dir)
		must(err)
		metadata(info, os.Geteuid(), gid, 02700)
		link := filepath.Join(a[1], "group-link")
		must(os.Symlink("group-file", link))
		info, err = os.Lstat(link)
		must(err)
		metadata(info, os.Geteuid(), gid, 0777)
	case "stress", "verify-stress":
		uid, gid := os.Geteuid(), os.Getegid()
		for i := 0; i < 40; i++ {
			path := filepath.Join(a[1], fmt.Sprintf("caller-%d-%d", uid, i))
			if a[0] == "stress" {
				create(path, uid, gid)
			} else {
				verify(path, uid, gid)
			}
		}
	default:
		panic("unknown probe command")
	}
	fmt.Println("ok")
}
