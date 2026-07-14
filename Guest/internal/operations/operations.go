//go:build linux

package operations

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"dev.cengine/guest/internal/disk"
	"golang.org/x/sys/unix"
)

type Statistics struct { CPUTotalNanoseconds uint64 `json:"cpuTotalNanoseconds"`; CPUUserNanoseconds uint64 `json:"cpuUserNanoseconds"`; CPUSystemNanoseconds uint64 `json:"cpuSystemNanoseconds"`; MemoryUsage uint64 `json:"memoryUsage"`; MemoryCache uint64 `json:"memoryCache"`; PIDs uint64 `json:"pids"`; BlockReadBytes uint64 `json:"blockReadBytes"`; BlockWriteBytes uint64 `json:"blockWriteBytes"`; Networks []NetworkStatistics `json:"networks"` }
type NetworkStatistics struct { Name string `json:"name"`; RXBytes uint64 `json:"rxBytes"`; RXPackets uint64 `json:"rxPackets"`; RXErrors uint64 `json:"rxErrors"`; TXBytes uint64 `json:"txBytes"`; TXPackets uint64 `json:"txPackets"`; TXErrors uint64 `json:"txErrors"` }
type Process struct { PID int `json:"pid"`; User string `json:"user"`; Command string `json:"command"` }
type Ownership struct { Path string `json:"path"`; User uint32 `json:"user"`; Group uint32 `json:"group"` }

func CopyIn(source, destination string, ownership []Ownership) error {
	root, err := mountedRoot(); if err != nil { return err }
	source = filepath.Join("/run/cengine/io", filepath.Clean("/"+source))
	target, err := containerPath(root, destination); if err != nil { return err }
	if err := copyContents(source, target); err != nil { return err }
	for _, owner := range ownership { path, err := archivePath(target, owner.Path); if err != nil { return err }; if err := os.Lchown(path, int(owner.User), int(owner.Group)); err != nil && !errors.Is(err, os.ErrNotExist) { return err } }
	return syncRoot(root)
}

func CopyOut(source, destination string) error {
	root, err := mountedRoot(); if err != nil { return err }
	from, err := containerPath(root, source); if err != nil { return err }
	to := filepath.Join("/run/cengine/io", filepath.Clean("/"+destination)); if err := os.RemoveAll(to); err != nil { return err }; if err := os.MkdirAll(to, 0755); err != nil { return err }
	return copyEntry(from, filepath.Join(to, filepath.Base(from)))
}

func Stats(pid int) (Statistics, error) {
	var result Statistics
	fields, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); if err != nil { return result, err }
	parts := strings.Fields(string(fields)); if len(parts) < 15 { return result, errors.New("invalid process stat") }
	user, _ := strconv.ParseUint(parts[13],10,64); system, _ := strconv.ParseUint(parts[14],10,64); result.CPUUserNanoseconds=user*10_000_000;result.CPUSystemNanoseconds=system*10_000_000;result.CPUTotalNanoseconds=result.CPUUserNanoseconds+result.CPUSystemNanoseconds
	status,_:=os.ReadFile(fmt.Sprintf("/proc/%d/status",pid));for _,line:=range strings.Split(string(status),"\n"){if strings.HasPrefix(line,"VmRSS:"){result.MemoryUsage=parseKB(line)}}
	ioData,_:=os.ReadFile(fmt.Sprintf("/proc/%d/io",pid));for _,line:=range strings.Split(string(ioData),"\n"){if strings.HasPrefix(line,"read_bytes:"){result.BlockReadBytes=parseValue(line)};if strings.HasPrefix(line,"write_bytes:"){result.BlockWriteBytes=parseValue(line)}}
	processes,_:=os.ReadDir(fmt.Sprintf("/proc/%d/root/proc",pid));for _,entry:=range processes{if entry.IsDir(){if _,err:=strconv.Atoi(entry.Name());err==nil{result.PIDs++}}}
	networkRoot:=fmt.Sprintf("/proc/%d/root/sys/class/net",pid);interfaces,_:=os.ReadDir(networkRoot);for _,entry:=range interfaces{if entry.Name()=="lo"{continue};base:=filepath.Join(networkRoot,entry.Name(),"statistics");result.Networks=append(result.Networks,NetworkStatistics{Name:entry.Name(),RXBytes:readUint(base+"/rx_bytes"),RXPackets:readUint(base+"/rx_packets"),RXErrors:readUint(base+"/rx_errors"),TXBytes:readUint(base+"/tx_bytes"),TXPackets:readUint(base+"/tx_packets"),TXErrors:readUint(base+"/tx_errors")})}
	return result,nil
}

func Top(pid int) ([]Process,error) { root:=fmt.Sprintf("/proc/%d/root/proc",pid);entries,err:=os.ReadDir(root);if err!=nil{return nil,err};var result []Process;for _,entry:=range entries{number,err:=strconv.Atoi(entry.Name());if err!=nil||!entry.IsDir(){continue};command,_:=os.ReadFile(filepath.Join(root,entry.Name(),"cmdline"));command=stringsToSpaces(command);status,_:=os.ReadFile(filepath.Join(root,entry.Name(),"status"));user:="0";for _,line:=range strings.Split(string(status),"\n"){if strings.HasPrefix(line,"Uid:"){fields:=strings.Fields(line);if len(fields)>1{user=fields[1]};break}};result=append(result,Process{PID:number,User:user,Command:string(command)})};return result,nil }

func mountedRoot()(string,error){root:="/run/cengine/rootfs";if err:=disk.EnsureExt4("/dev/vda",root,"cengine-root");err!=nil{return "",err};return root,nil}
func containerPath(root,value string)(string,error){if !filepath.IsAbs(value){return "",syscall.EINVAL};clean:=filepath.Clean(value);if clean=="/"{return root,nil};relative:=strings.TrimPrefix(clean,"/");if relative==".."||strings.HasPrefix(relative,"../"){return "",syscall.EPERM};return filepath.Join(root,relative),nil}
func archivePath(root,value string)(string,error){if value==""||filepath.IsAbs(value){return "",syscall.EINVAL};clean:=filepath.Clean(value);if clean==".."||strings.HasPrefix(clean,"../"){return "",syscall.EPERM};if clean=="."{return root,nil};return filepath.Join(root,clean),nil}
func copyContents(source,target string)error{if err:=os.MkdirAll(target,0755);err!=nil{return err};entries,err:=os.ReadDir(source);if err!=nil{return err};for _,entry:=range entries{if err:=copyEntry(filepath.Join(source,entry.Name()),filepath.Join(target,entry.Name()));err!=nil{return err}};return nil}
func copyEntry(source,target string)error{info,err:=os.Lstat(source);if err!=nil{return err};if info.IsDir(){if err:=os.MkdirAll(target,info.Mode().Perm());err!=nil{return err};entries,err:=os.ReadDir(source);if err!=nil{return err};for _,entry:=range entries{if err:=copyEntry(filepath.Join(source,entry.Name()),filepath.Join(target,entry.Name()));err!=nil{return err}};return nil};if info.Mode()&os.ModeSymlink!=0{value,err:=os.Readlink(source);if err!=nil{return err};_ = os.RemoveAll(target);return os.Symlink(value,target)};if !info.Mode().IsRegular(){return fmt.Errorf("unsupported transfer entry %s",source)};input,err:=os.Open(source);if err!=nil{return err};defer input.Close();_ = os.RemoveAll(target);output,err:=os.OpenFile(target,os.O_CREATE|os.O_EXCL|os.O_WRONLY,info.Mode().Perm());if err!=nil{return err};_,copyErr:=io.Copy(output,input);closeErr:=output.Close();if copyErr!=nil{return copyErr};return closeErr}
func syncRoot(path string)error{fd,err:=unix.Open(path,unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC,0);if err!=nil{return err};defer unix.Close(fd);return unix.Syncfs(fd)}
func parseKB(line string)uint64{return parseValue(line)*1024};func parseValue(line string)uint64{fields:=strings.Fields(line);if len(fields)<2{return 0};value,_:=strconv.ParseUint(fields[1],10,64);return value};func readUint(path string)uint64{data,_:=os.ReadFile(path);value,_:=strconv.ParseUint(strings.TrimSpace(string(data)),10,64);return value};func stringsToSpaces(value []byte)[]byte{for index:=range value{if value[index]==0{value[index]=' '}};return []byte(strings.TrimSpace(string(value)))}
