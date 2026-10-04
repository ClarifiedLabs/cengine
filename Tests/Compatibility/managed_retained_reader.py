"""One prestarted, owned baseline exec; no exec admission after the fence."""
import struct
import time

import managed_prepare_faults as p
from volume_probe import close_exec_stream


class RetainedReader:
    def __init__(self, api, owner, remaining, *, command="retained-wait"):
        p.require(command in ("retained-wait", "root-wait"), "closed independent-reader command")
        self.api, self.remaining = api, remaining
        self.deadline = time.monotonic() + min(10, remaining())
        self.stream = None
        self.output = bytearray()
        self.received = 0
        self.triggered = False
        self.identifier = api.exec_create(owner.id, ["/probe", command],
            stdin=True, stdout=True, stderr=True, tty=False)["Id"]
        try:
            self.stream = api.exec_start(self.identifier, socket=True)
            self.sock = getattr(self.stream, "_sock", self.stream)
            ready = self.line()
            p.exact(ready, {"ready", "readerPID"})
            p.integer(ready["readerPID"], 2**31 - 1, 1)
            self.reader_pid = ready["readerPID"]
            p.require(ready["ready"] is True and not self.output, "prestarted reader ready")
        except BaseException:
            self.close()
            raise

    def timeout(self):
        value = min(self.remaining(), self.deadline - time.monotonic())
        p.require(value > 0, "absolute reader deadline")
        self.sock.settimeout(value)

    def exact(self, size, *, eof=False):
        data = bytearray()
        while len(data) < size:
            self.timeout()
            chunk = self.sock.recv(size - len(data))
            if not chunk:
                p.require(eof and not data, "complete reader frame")
                return None
            data.extend(chunk)
            self.received += len(chunk)
            p.require(self.received <= 131072, "total reader output bound")
        return bytes(data)

    def frame(self, *, eof=False):
        header = self.exact(8, eof=eof)
        if header is None:
            return None
        channel, length = struct.unpack(">BxxxI", header)
        p.require(header[1:4] == b"\0\0\0" and channel == 1 and 0 < length <= 131064,
            "bounded stdout-only reader frame")
        return self.exact(length)

    def line(self):
        while b"\n" not in self.output:
            self.output.extend(self.frame())
        line, _, rest = self.output.partition(b"\n")
        self.output = bytearray(rest)
        return p.decode(bytes(line), 131072, canonical_only=False)

    def snapshot(self):
        p.require(not self.triggered and not self.output, "one reader trigger after ready")
        self.triggered = True
        try:
            self.timeout()
            self.sock.sendall(b"\x01")
            value = self.line()
            p.require(not self.output and self.frame(eof=True) is None, "reader output completed")
            # The source/hash-pinned guest supervisor emits this only after
            # waitpid joins its exact prestarted child. API exec inspection is a
            # fenced host status here, not a fresh observation of guest death.
            p.exact(value, {"version", "readerPID", "exitCode", "snapshot"})
            p.integer(value["version"], 1, 1)
            p.integer(value["readerPID"], self.reader_pid, self.reader_pid)
            p.integer(value["exitCode"], 0, 0)
            p.require(type(value["snapshot"]) is dict, "joined reader snapshot")
            self.join_receipt = {key: value[key] for key in ("version", "readerPID", "exitCode")}
            return value["snapshot"]
        finally:
            self.close()

    def close(self):
        # Stream closure is NOT process join or backing evidence. The fixed
        # guest watchdog bounds idle input; owned workload containment handles
        # failure (including a kernel-blocked syscall) in the existing runner.
        if self.stream is not None:
            stream, self.stream = self.stream, None
            close_exec_stream(stream)
