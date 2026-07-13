//go:build linux

package supervisor

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"dev.cengine/guest/internal/protocol"
	"golang.org/x/sys/unix"
)

const execStage1Argument = "cengine-exec-stage1"
const execStage2Argument = "cengine-exec-stage2"

func IsExecStage1(arguments []string) bool { return len(arguments)==3 && arguments[1]==execStage1Argument }
func IsExecStage2(arguments []string) bool { return len(arguments)==2 && arguments[1]==execStage2Argument }

func RunExecStage1(pid int) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	rootFD,err:=unix.Open(fmt.Sprintf("/proc/%d/root",pid),unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC,0);if err!=nil{return fmt.Errorf("open workload root: %w",err)}
	root:=os.NewFile(uintptr(rootFD),"workload-root");if root==nil{_ = unix.Close(rootFD);return errors.New("workload root is unavailable")};defer root.Close()
	if err:=joinWorkloadNamespaces(pid, namespaceOperations{unshare:unix.Unshare,open:unix.Open,setns:unix.Setns,close:unix.Close});err!=nil{return err}
	spec:=os.NewFile(3,"exec-spec");if spec==nil{return errors.New("exec specification is unavailable")}
	command:=exec.Command("/proc/self/exe",execStage2Argument);command.ExtraFiles=[]*os.File{spec,root};command.Stdin=os.Stdin;command.Stdout=os.Stdout;command.Stderr=os.Stderr
	if err:=command.Run();err!=nil{if exit,ok:=err.(*exec.ExitError);ok{return exit};return err};return nil
}

type namespaceOperations struct {
	unshare func(int) error
	open func(string,int,uint32)(int,error)
	setns func(int,int) error
	close func(int) error
}

func joinWorkloadNamespaces(pid int, operations namespaceOperations) error {
	if err:=operations.unshare(unix.CLONE_FS);err!=nil{return fmt.Errorf("unshare filesystem context: %w",err)}
	for _,namespace:=range []struct{name string;flag int}{{"mnt",unix.CLONE_NEWNS},{"uts",unix.CLONE_NEWUTS},{"ipc",unix.CLONE_NEWIPC},{"net",unix.CLONE_NEWNET},{"cgroup",unix.CLONE_NEWCGROUP},{"pid",unix.CLONE_NEWPID}} {
		fd,err:=operations.open(fmt.Sprintf("/proc/%d/ns/%s",pid,namespace.name),unix.O_RDONLY|unix.O_CLOEXEC,0);if err!=nil{return err};err=operations.setns(fd,namespace.flag);_ = operations.close(fd);if err!=nil{return fmt.Errorf("join %s namespace: %w",namespace.name,err)}
	}
	return nil
}

func RunExecStage2() error {
	file:=os.NewFile(3,"exec-spec");if file==nil{return errors.New("exec specification is unavailable")};defer file.Close();data,err:=io.ReadAll(io.LimitReader(file,protocol.MaxControlFrame));if err!=nil{return err};var spec protocol.ExecSpec;if err:=json.Unmarshal(data,&spec);err!=nil{return err}
	root:=os.NewFile(4,"workload-root");if root==nil{return errors.New("workload root is unavailable")};defer root.Close();if err:=enterExecRoot(int(root.Fd()),unix.Fchdir,unix.Chroot);err!=nil{return err};working:=spec.WorkingDirectory;if working==""{working="/"};if err:=os.Chdir(working);err!=nil{return err}
	uid,gid,err:=parseExecUser(spec.User);if err!=nil{return err};if err:=unix.Setgroups(nil);err!=nil{return err};if err:=unix.Setgid(gid);err!=nil{return err};if err:=unix.Setuid(uid);err!=nil{return err}
	environment:=spec.Environment;if len(environment)==0{environment=[]string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}};for _,value:=range environment{parts:=strings.SplitN(value,"=",2);if len(parts)==2{_ = os.Setenv(parts[0],parts[1])}}
	if len(spec.Arguments)==0{return errors.New("exec requires arguments")};path,err:=exec.LookPath(spec.Arguments[0]);if err!=nil{return err};return unix.Exec(path,spec.Arguments,environment)
}

func enterExecRoot(fd int, fchdir func(int)error, chroot func(string)error) error {
	if err:=fchdir(fd);err!=nil{return fmt.Errorf("enter workload root: %w",err)}
	if err:=chroot(".");err!=nil{return fmt.Errorf("chroot workload: %w",err)}
	return nil
}

func (s *Supervisor) PrepareExec(spec protocol.ExecSpec) error { if spec.ID==""||len(spec.Arguments)==0{return errors.New("exec requires id and arguments")};s.mu.Lock();defer s.mu.Unlock();if s.command==nil{return errors.New("workload is not running")};if _,exists:=s.execStatus[spec.ID];exists{return errors.New("exec already exists")};s.execStatus[spec.ID]=protocol.ProcessStatus{Status:"created"};data,err:=json.Marshal(spec);if err!=nil{return err};return os.WriteFile("/run/cengine/io/exec-"+spec.ID+".json",data,0600) }

func (s *Supervisor) StartExec(id string)(protocol.ProcessStatus,error){s.mu.Lock();if s.command==nil||s.command.Process==nil{s.mu.Unlock();return protocol.ProcessStatus{},errors.New("workload is not running")};if _,exists:=s.execs[id];exists{s.mu.Unlock();return s.execStatus[id],errors.New("exec is running")};pid:=s.command.Process.Pid;s.mu.Unlock();data,err:=os.ReadFile("/run/cengine/io/exec-"+id+".json");if err!=nil{return protocol.ProcessStatus{},err};reader,writer,err:=os.Pipe();if err!=nil{return protocol.ProcessStatus{},err};stdout,err:=os.OpenFile("/run/cengine/io/exec-"+id+"-stdout",os.O_CREATE|os.O_APPEND|os.O_WRONLY,0644);if err!=nil{return protocol.ProcessStatus{},err};stderr,err:=os.OpenFile("/run/cengine/io/exec-"+id+"-stderr",os.O_CREATE|os.O_APPEND|os.O_WRONLY,0644);if err!=nil{stdout.Close();return protocol.ProcessStatus{},err};stdinReader,stdinWriter:=io.Pipe();command:=exec.Command("/proc/self/exe",execStage1Argument,strconv.Itoa(pid));command.ExtraFiles=[]*os.File{reader};command.Stdout=stdout;command.Stderr=stderr;command.Stdin=stdinReader;if err:=command.Start();err!=nil{reader.Close();writer.Close();stdout.Close();stderr.Close();stdinReader.Close();stdinWriter.Close();return protocol.ProcessStatus{},err};reader.Close();stdout.Close();stderr.Close();stdinReader.Close();if _,err:=writer.Write(data);err!=nil{writer.Close();stdinWriter.Close();_ = command.Process.Kill();return protocol.ProcessStatus{},err};writer.Close();status:=protocol.ProcessStatus{Status:"running",PID:command.Process.Pid};s.mu.Lock();s.execs[id]=command;s.execStatus[id]=status;s.mu.Unlock();go s.reapExec(id,command);go pumpInput("/run/cengine/io/exec-"+id+"-stdin",stdinWriter,command);return status,nil}

func (s *Supervisor) ExecStatus(id string)protocol.ProcessStatus{s.mu.Lock();defer s.mu.Unlock();return s.execStatus[id]}
func (s *Supervisor) SignalExec(id string,signal int)error{s.mu.Lock();defer s.mu.Unlock();command:=s.execs[id];if command==nil||command.Process==nil{return errors.New("exec is not running")};if signal<=0||signal>=65{return syscall.EINVAL};return unix.Kill(command.Process.Pid,unix.Signal(signal))}
func (s *Supervisor) WaitExec(id string)protocol.ProcessStatus{for{status:=s.ExecStatus(id);if status.Status!="running"{return status};_ = unix.Nanosleep(&unix.Timespec{Nsec:20_000_000},nil)}}
func (s *Supervisor) reapExec(id string,command *exec.Cmd){err:=command.Wait();code:=0;if command.ProcessState!=nil{code=command.ProcessState.ExitCode();if status,ok:=command.ProcessState.Sys().(syscall.WaitStatus);ok&&status.Signaled(){code=128+int(status.Signal())}};if err!=nil&&code<0{code=255};s.mu.Lock();delete(s.execs,id);s.execStatus[id]=protocol.ProcessStatus{Status:"exited",ExitCode:&code};s.mu.Unlock()}
func parseExecUser(value string)(int,int,error){if value==""{return 0,0,nil};parts:=strings.SplitN(value,":",2);uid,err:=strconv.Atoi(parts[0]);gid:=uid;if err!=nil{passwd,readErr:=os.ReadFile("/etc/passwd");if readErr!=nil{return 0,0,readErr};uid=-1;for _,line:=range strings.Split(string(passwd),"\n"){fields:=strings.Split(line,":");if len(fields)>=4&&fields[0]==parts[0]{uid,_=strconv.Atoi(fields[2]);gid,_=strconv.Atoi(fields[3]);break}};if uid<0{return 0,0,fmt.Errorf("user %s not found",parts[0])}};if len(parts)>1&&parts[1]!=""{if value,parseErr:=strconv.Atoi(parts[1]);parseErr==nil{gid=value}else{groups,_:=os.ReadFile("/etc/group");for _,line:=range strings.Split(string(groups),"\n"){fields:=strings.Split(line,":");if len(fields)>=3&&fields[0]==parts[1]{gid,_=strconv.Atoi(fields[2]);break}}}};return uid,gid,nil}
