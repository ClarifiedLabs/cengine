#!/usr/bin/env python3
"""Engine-free diagnostics guards; portable Go tests use actual pure fixture code.

Never execute the Linux helper or native mounted tests here. The parent-owned
RTM-081/082/083 rerun is required for actual procfs/kernel-stack evidence.
"""
from pathlib import Path
import os
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "Tests/Compatibility/fixtures/managed-fuse-native.go"
NATIVE = ROOT / "Guest/internal/storagefuse/native_mounted_linux_test.go"
BURST = ROOT / "Guest/internal/storagefuse/native_write_burst_linux_test.go"


def declaration(source, signature):
    start = source.index(signature)
    end = source.index("\n}", start) + 2  # top-level gofmt delimiter, not an inner block
    return source[start:end]


class DiagnosticsGuards(unittest.TestCase):
    def test_observer_bound_pin_before_wait_and_no_numeric_resignal(self):
        source = HELPER.read_text()
        runner = declaration(source, "func executeNative(")
        self.assertLess(runner.index("pinNativeProcess(command)"), runner.index("command.Wait()"))
        self.assertIn("command.SysProcAttr.PidFD = &pidFD", runner)
        self.assertIn("unix.PidfdSendSignal(pidFD, unix.SIGKILL, nil, 0)", runner)
        self.assertIn("if joined && pidFD >= 0", runner)
        self.assertNotIn("syscall.Kill", runner)
        self.assertIn("time.NewTimer(30 * time.Second)", runner)
        self.assertIn("time.After(time.Second)", runner)
        self.assertIn("time.After(2 * time.Second)", runner)
        self.assertIn("probe != nil && !observing", runner)
        capture = declaration(source, "func (p *nativeProcessProbe) capture()")
        self.assertNotIn('"/proc/', capture)  # only openat from the pre-Wait pin
        self.assertIn("current != p.identity", capture)
        self.assertIn("Readdirnames(33)", capture)
        self.assertIn("names = names[:32]", capture)
        self.assertIn("maxLog/4 - 256", capture)
        self.assertIn('[]string{"wchan", "syscall", "stack"}', capture)
        self.assertIn("procRead(task, field, 1024)", capture)
        self.assertIn("identity.pid == tid", capture)
        self.assertIn("identity.parent == p.identity.parent", capture)
        self.assertIn("identity.group == p.identity.group", capture)
        self.assertNotIn("Signal", capture)
        self.assertNotIn("Kill", capture)
        pin = declaration(source, "func pinNativeProcess(")
        self.assertIn("identity.pid != command.Process.Pid", pin)
        self.assertIn("identity.parent != os.Getpid()", pin)
        self.assertIn("identity.group != command.Process.Pid", pin)
        self.assertIn("unix.O_NOFOLLOW", pin)
        run = declaration(source, "func run(r *result,")
        self.assertIn("&boundedOutput{limit: maxLog / 2, readback: readback}", run)
        self.assertIn("make(chan time.Time, 1)", run)
        self.assertIn("executeNative(ctx, command, readback)", run)
        self.assertIn("readback = nil", runner)
        self.assertIn("readbackDue = nil", runner)
        self.assertEqual(runner.count("time.NewTimer("), 2)
        self.assertIn("time.Until(detected.Add(2 * time.Second))", runner)
        self.assertIn('label = "observation-readback-2s"', runner)
        self.assertIn('label = "observation-30s"', runner)
        self.assertIn('"D %s observed_ms=%d\\n", label, time.Since(started).Milliseconds()', runner)
        self.assertIn("diagnostic = append(diagnostic, snapshot...)", runner)
        self.assertNotIn("Sleep", runner)
        self.assertLess(runner.index("if ctx.Err() != nil"), runner.index("go func() { capture <- probe.capture() }()"))
        self.assertIn("len(raw) > maxLog", run)
        self.assertIn("l.log.Write(raw)", run)
        self.assertIn("selectedCaseBudget(r.Case)", run)
        self.assertIn("context.WithTimeout(context.Background(), outerLimit)", run)
        budget = declaration(source, "func selectedCaseBudget(")
        self.assertIn('return "-test.timeout=90s", 95 * time.Second, nil', budget)
        self.assertIn('return "-test.timeout=180s", 190 * time.Second, nil', budget)
        self.assertNotIn("asyncpreemptoff", source)

    def test_workload_operations_and_closed_phase_words_unchanged(self):
        source = BURST.read_text()
        for required in ("i < 1000", "i%10 == 0", "(i * 37) % len(model)",
                         "model := make([]byte, 4096)", "model[offset] = value[0]",
                         "model[len(model)-1] = 0", "nativeReadback(name, model)"):
            self.assertIn(required, source)
        self.assertEqual(source.count("unix.Pwrite("), 1)
        self.assertEqual(source.count("unix.Ftruncate("), 3)
        self.assertEqual(source.count("unix.Fsync("), 1)
        self.assertNotIn("Sleep", source)
        self.assertNotIn("exec.", source)
        self.assertNotIn("os.ReadFile(", source)
        readback = declaration((BURST.parent / "native_readback_test.go").read_text(), "func nativeReadback(")
        self.assertIn("unix.Open(name, unix.O_RDONLY|unix.O_CLOEXEC, 0)", readback)
        self.assertIn("unix.Fstat(fd, &stat)", readback)
        self.assertIn("stat.Mode&unix.S_IFMT != unix.S_IFREG", readback)
        self.assertIn("stat.Size != int64(len(model))", readback)
        self.assertIn("make([]byte, len(model)+1)", readback)
        self.assertIn("n != len(model)", readback)
        self.assertIn("bytes.Equal(actual[:n], model)", readback)
        self.assertEqual(readback.count("unix.Pread("), 1)
        self.assertEqual(readback.count("unix.Close(fd)"), 1)
        self.assertNotIn("os.", readback)
        self.assertNotIn("O_NONBLOCK", readback)
        native = NATIVE.read_text()
        self.assertIn("var nativePhaseStarted = time.Now()", native)
        phase = declaration(native, "func nativePhase(")
        self.assertIn('"P %s %d %c %d\\n"', phase)
        self.assertIn("time.Since(nativePhaseStarted).Milliseconds()", phase)
        words = set(re.findall(r'nativePhase\("([^"]+)"', source + NATIVE.read_text()))
        self.assertEqual(words, {"open", "size", "write", "shrink", "grow", "sync", "close", "defer-close", "readback",
                                 "setup", "remove", "authority", "cleanup-close", "data-join", "retire",
                                 "mount", "workload", "graceful"})
        for operation in ("open", "size", "write", "shrink", "grow", "sync", "close", "defer-close", "readback"):
            self.assertRegex(source, r'nativePhase\("' + operation + r'", [^,]+, false\)')
            self.assertRegex(source, r'nativePhase\("' + operation + r'", [^,]+, true\)')

    def test_actual_portable_parser_output_and_phase_code_with_race(self):
        source = HELPER.read_text()
        snippets = [declaration(source, signature) for signature in (
            "type procIdentity struct", "func parseProcIdentity(", "type readbackPhaseParser struct",
            "func (p *readbackPhaseParser) feed(", "type boundedOutput struct",
            "func (b *boundedOutput) Write(", "func (b *boundedOutput) snapshot(")]
        native = NATIVE.read_text()
        snippets.append(re.search(r'^var nativePhaseStarted = time.Now\(\)$', native, re.M).group(0))
        snippets.append("var nativePhaseOutput io.Writer = os.Stdout")
        snippets.append(declaration(native, "func nativePhase("))
        code = 'package diagnostics\nimport("bytes";"errors";"fmt";"io";"os";"strconv";"strings";"sync";"time")\nconst maxLog=128*1024\n'
        tests = r'''package diagnostics
import("bytes";"fmt";"io";"os";"regexp";"strconv";"strings";"sync";"testing";"time")
func stat(comm string) []byte { return []byte("42 ("+comm+") S 7 42 "+strings.Repeat("0 ",16)+"12345 0\n") }
func TestProcIdentity(t *testing.T) {
 for _, comm := range []string{"native.test", "odd ) ) name", "x\nwith newline"} {
  got, err := parseProcIdentity(stat(comm)); if err != nil || got != (procIdentity{42,7,42,12345}) { t.Fatalf("%+v %v",got,err) }
 }
 for _, raw := range [][]byte{nil, []byte("42 x S"), []byte("42 (x) S"), bytes.Repeat([]byte("x"),4097),
  bytes.Replace(stat("x"), []byte("S 7 42"), []byte("S -1 42"), 1),
  bytes.Replace(stat("x"), []byte("12345"), []byte("0"), 1)} {
  if _, err := parseProcIdentity(raw); err == nil { t.Fatal("accepted malformed identity") }
 }
 old,_:=parseProcIdentity(stat("old")); next,_:=parseProcIdentity(bytes.Replace(stat("new"),[]byte("12345"),[]byte("12346"),1))
 if old==next { t.Fatal("reused PID birth accepted") }
}
func TestOutputSplitAndConcurrentBound(t *testing.T) {
 out:=&boundedOutput{limit:maxLog/2}; var wg sync.WaitGroup
 for i:=0;i<8;i++ { wg.Add(1);go func(){defer wg.Done();for j:=0;j<4096;j++{out.Write([]byte("abcd"))};out.snapshot()}() };wg.Wait()
 raw,overflow:=out.snapshot(); if len(raw)>maxLog/2||!overflow { t.Fatal(len(raw),overflow) }
 snapshot,_:=out.snapshot(); raw[0]='z'; if snapshot[0]=='z' {t.Fatal("snapshot aliases live buffer")}
 diagnostic:=&boundedOutput{limit:maxLog/4-256}; diagnostic.Write(bytes.Repeat([]byte("d"),maxLog/4-256))
 diagnostic.Write([]byte("exceeds bound"));d,over:=diagnostic.snapshot()
 if !over || len(d)!=maxLog/4-256 {t.Fatal("snapshot bound")}
 if len(snapshot)+2*len(d)+512>maxLog {t.Fatal("combined log unbounded")}
}
func TestReadbackParserExactChunksAndSingleTrigger(t *testing.T) {
 valid:=[]byte("P readback 0 b 12345\n")
 for split:=0;split<len(valid);split++ {
  var p readbackPhaseParser
  if p.feed(valid[:split]) || !p.feed(valid[split:]) || p.feed(valid) {t.Fatalf("split %d",split)}
 }
 var p readbackPhaseParser; fires:=0
 for _,v:=range valid {if p.feed([]byte{v}) {fires++}}
 if fires!=1 {t.Fatal(fires)}
 for _,stamp:=range []string{"0","1","9223372036854775807"} {
  var p readbackPhaseParser;if !p.feed([]byte("P readback 0 b "+stamp+"\n")){t.Fatal(stamp)}
 }
 for _,line:=range []string{"P readback 0 b", "P readback 0 b ", "P readback 0 b -1", "P readback 0 b +1",
  "P readback 0 b 1.0", "P readback 0 b 1e3", "P readback 0 b 9223372036854775808",
  "P readback 0 b 1 ", "P readback 0 b 1\r", " P readback 0 b 1", "prefix P readback 0 b 1",
  "P readback 0 b 1 extra", "P readback 0 b 1\x00", "P readback 0 e 1", "P readback 1 b 1",
  "P readback 00 b 1", "P readback -1 b 1", "P readback 0  b 1", "P readback\t0 b 1", "P write 0 b 1",
  "P setup 0 b 1", "P readback 0 b ١", "P readback 0 b "+strings.Repeat("0",65)} {
  var p readbackPhaseParser
  if p.feed([]byte(line+"\n")){t.Fatalf("accepted %q",line)}
  if !p.feed(valid){t.Fatalf("no recovery after %q",line)}
 }
 var bounded readbackPhaseParser
 for i:=0;i<10000;i++ {if bounded.feed(bytes.Repeat([]byte("x"),4096)){t.Fatal("noise")}}
 if bounded.used>len(bounded.line) || !bounded.discard {t.Fatal("unbounded pending line")}
 if bounded.feed(valid) || !bounded.feed(valid) {t.Fatal("oversized line suffix/recovery")}
}
func TestReadbackOutputNotificationBoundAndRace(t *testing.T) {
 event:=make(chan time.Time,1);out:=&boundedOutput{limit:maxLog/2,readback:event}
 before:=time.Now()
 out.Write([]byte("P readback 0 b "));out.Write([]byte("9223372036854775807\n"))
 var observed time.Time
 select {case observed=<-event:default:t.Fatal("missing notification")}
 if observed.Before(before)||observed.After(time.Now()){t.Fatal("native stamp scheduled observation")}
 // Once only, even when racing complete valid lines and snapshots.
 var wg sync.WaitGroup
 for i:=0;i<8;i++{wg.Add(1);go func(){defer wg.Done();for j:=0;j<32;j++{out.Write([]byte("P readback 0 b 0\n"));out.snapshot()}}()};wg.Wait()
 select {case <-event:t.Fatal("rearmed");default:}
 limited:=&boundedOutput{limit:4,readback:make(chan time.Time,1)}
 if _,err:=limited.Write([]byte("P readback 0 b 0\n"));err==nil{t.Fatal("output overflow accepted")}
 select {case <-limited.readback:t.Fatal("overflow armed observer");default:}
 // Diagnostics cannot introduce a wait into the stdout copy goroutine.
 blocked:=&boundedOutput{limit:100,readback:make(chan time.Time)}
 complete:=make(chan struct{});go func(){blocked.Write([]byte("P readback 0 b 0\n"));close(complete)}()
 select {case <-complete:case <-time.After(time.Second):t.Fatal("notification blocked output")}
}
func TestExactPhaseBudget(t *testing.T) {
 // Only portable fixed-word formatter is executed, never mounted operations.
 file,err:=os.CreateTemp(t.TempDir(),"phase");if err!=nil{t.Fatal(err)};defer file.Close()
 old:=nativePhaseOutput;nativePhaseOutput=file;defer func(){nativePhaseOutput=old}()
 // Worst-case five-digit timestamp within the unchanged outer deadline.
 oldStarted:=nativePhaseStarted;nativePhaseStarted=time.Now().Add(-95*time.Second);defer func(){nativePhaseStarted=oldStarted}()
 phase:=func(word string,index int){nativePhase(word,index,false);nativePhase(word,index,true)}
 for i:=0;i<1000;i++{phase("write",i);if i%10==0{phase("shrink",i);phase("grow",i)}}
 for _,word:=range []string{"open","size","sync","close","defer-close","readback","setup","remove","authority","cleanup-close","data-join","retire","mount","workload","graceful"}{phase(word,0)}
 phase("readback",1)
 if _,err=file.Seek(0,0);err!=nil{t.Fatal(err)};raw,err:=io.ReadAll(file);if err!=nil{t.Fatal(err)}
 if len(raw)>=maxLog/2-4096{t.Fatalf("phase bytes %d",len(raw))}
 if !bytes.Contains(raw,[]byte("P write 999 e ")){t.Fatal("last operation missing")}
 pattern:=regexp.MustCompile(`^P [a-z-]+ [0-9]+ [be] ([0-9]+)$`);previous:=int64(0)
 for _,line:=range strings.Split(strings.TrimSpace(string(raw)),"\n"){
  matches:=pattern.FindStringSubmatch(line);if matches==nil{t.Fatalf("phase envelope %q",line)}
  elapsed,err:=strconv.ParseInt(matches[1],10,64);if err!=nil||elapsed<95000||elapsed<previous{t.Fatal("nonmonotonic phase",line)};previous=elapsed
  var word string;var index int;var edge byte;var stamp int64
  if n,err:=fmt.Sscanf(line,"P %s %d %c %d",&word,&index,&edge,&stamp);err!=nil||n!=4{t.Fatal(err)}
 }
}
'''
        with tempfile.TemporaryDirectory(prefix="cengine-native-diagnostics-") as directory:
            root = Path(directory)
            (root / "go.mod").write_text("module diagnostics\ngo 1.25.0\n")
            (root / "diagnostics.go").write_text(code + "\n".join(snippets))
            (root / "diagnostics_test.go").write_text(tests)
            environment = dict(os.environ, GOPROXY="off", GOSUMDB="off", GOWORK="off")
            result = subprocess.run(["go", "test", "-race", "-count=1", "./..."], cwd=root,
                                    env=environment, capture_output=True, timeout=90)
            self.assertEqual(result.returncode, 0, result.stdout.decode() + result.stderr.decode())


if __name__ == "__main__":
    unittest.main()
