"""Closed advisory metadata only; never changes start acceptance or carries text.

The pipe carries one legacy byte or five closed enum bytes. Both ends are
nonblocking; the parent reads at most MAX_FRAME + 1 bytes AFTER actual wait,
then requires EOF, rejecting extra/missing/unknown data. No
stdout/stderr capture, additional timeout, retry, or filesystem artifact.
"""
import os
import subprocess

CATEGORIES = ("UNKNOWN", "SUCCESS", "MANAGED_STORAGE_OWNERSHIP_UNRESOLVED",
              "HTTP_CONFLICT_UNKNOWN", "HTTP_INTERNAL_ERROR", "HTTP_OTHER",
              "CONNECTION_LOST")
# RawManagedStorageBackend.failure default, EngineError(.conflict); Docker API
# dockerErrorResponse maps this to 409 and preserves message in SDK explanation.
OWNERSHIP = "managed storage ownership unresolved; preserve generation evidence"

# Frozen wire ordinals: do not reorder the legacy categories or these tables.
# PrivateWorkloadStorageCoordinator.Stage and WorkloadStorageProtocol enums.
STAGES = (None, "validate-held-disks", "connect-init", "hello-guard", "receipt-guard",
          "configure-guard", "configure-encode", "write-configure", "command-guard",
          "command-phase", "command-encode", "write-command", "read-frame",
          "read-length", "read-eof", "read-decode", "read-binding", "read-expectation",
          "terminal-binding", "guest-terminal", "reply-validate", "shim-response-decode",
          "shim-response-binding", "status-guard", "status-deadline")
KINDS = (None, "offer-keys", "install-certificate", "mount-phase",
         "prepare-compatibility-arm", "prepare", "close-phase", "start", "status", "abort")
ROLES = (None, "prepare", "runtime")
CODES = (None, "invalid-frame", "binding-mismatch", "scope-mismatch", "configuration",
         "sequence", "phase", "certificate", "mount", "prepare", "start", "aborted",
         "terminal", "internal")
PRIVATE_CATEGORIES = ("PRIVATE_WORKLOAD_STORAGE_CHANNEL_REFUSED",
                      "PRIVATE_WORKLOAD_STORAGE_OPERATION_REFUSED")
CHANNEL = "private workload storage channel refused; preserve generation evidence"
OPERATION = "private workload storage operation refused"
FIELDS = ("stage", "kind", "role", "code")
TABLES = (STAGES, KINDS, ROLES, CODES)
MAX_FRAME = 5


def _private_frame(value):
    if type(value) is not dict or value.keys() != {"category", *FIELDS}: return None
    category = value["category"]
    if type(category) is not str or category not in PRIVATE_CATEGORIES: return None
    values = tuple(value[field] for field in FIELDS)
    if any(item is not None and type(item) is not str for item in values): return None
    if any(item not in table for item, table in zip(values, TABLES)): return None
    stage, kind, role, code = values
    if category == PRIVATE_CATEGORIES[0]:
        if stage is None and any(item is not None for item in (kind, role, code)): return None
    elif stage is not None or kind is None or code is None:
        return None
    return bytes([len(CATEGORIES) + PRIVATE_CATEGORIES.index(category),
                  *(table.index(item) for item, table in zip(values, TABLES))])


def _private_text(value):
    if value["category"] == PRIVATE_CATEGORIES[0]:
        if value["stage"] is None: return CHANNEL
        prefix, names = CHANNEL, ("phase", "operation", "role", "guest-code")
    else:
        prefix, names = OPERATION, ("phase", "operation", "role", "guest")
    return prefix + " [" + " ".join(name + "=" + value[field]
        for name, field in zip(names, FIELDS) if value[field] is not None) + "]"


def _classify_private(explanation):
    for category, prefix, names in (
        (PRIVATE_CATEGORIES[0], CHANNEL, ("phase", "operation", "role", "guest-code")),
        (PRIVATE_CATEGORIES[1], OPERATION, ("phase", "operation", "role", "guest")),
    ):
        value = {"category": category, **dict.fromkeys(FIELDS)}
        if explanation != prefix:
            if not explanation.startswith(prefix + " [") or not explanation.endswith("]"): continue
            for token in explanation[len(prefix) + 2:-1].split(" "):
                pair = token.split("=")
                if len(pair) != 2 or pair[0] not in names: break
                field = FIELDS[names.index(pair[0])]
                if value[field] is not None: break
                value[field] = pair[1]
            else:
                if _private_frame(value) is not None and _private_text(value) == explanation:
                    return value
            continue
        if _private_frame(value) is not None: return value
    return "HTTP_CONFLICT_UNKNOWN"


def classify(status, explanation):
    if status == 409:
        if type(explanation) is not str or len(explanation) > 256:
            return "HTTP_CONFLICT_UNKNOWN"
        if explanation == OWNERSHIP: return "MANAGED_STORAGE_OWNERSHIP_UNRESOLVED"
        return _classify_private(explanation)
    return "HTTP_INTERNAL_ERROR" if status == 500 else "HTTP_OTHER"


def emit(fd, category):
    if type(fd) is not int: return
    try:
        os.set_blocking(fd, False)
        frame = _private_frame(category)
        if frame is None:
            frame = bytes([CATEGORIES.index(category)
                if type(category) is str and category in CATEGORIES else 0])
        os.write(fd, frame)
    except OSError:
        pass  # Advisory loss must not change exact SDK result.
    finally:
        try: os.close(fd)
        except OSError: pass


def spawn(command, *, popen=subprocess.Popen):
    read_fd, write_fd = os.pipe()
    try:
        os.set_blocking(read_fd, False)
        os.set_blocking(write_fd, False)
        process = popen([*command, str(write_fd)], pass_fds=(write_fd,),
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, start_new_session=True)
        process._start_diagnostic_fd = read_fd
        return process
    except BaseException:
        os.close(read_fd)
        raise
    finally:
        os.close(write_fd)


def discard(process):
    fd = getattr(process, "_start_diagnostic_fd", None)
    if type(fd) is int:
        process._start_diagnostic_fd = None
        try: os.close(fd)
        except OSError: pass


def receive(process):
    fd = getattr(process, "_start_diagnostic_fd", None)
    if type(fd) is not int: return "UNKNOWN"
    try:
        os.set_blocking(fd, False)
        raw = os.read(fd, MAX_FRAME + 1)
        if len(raw) not in (1, MAX_FRAME) or os.read(fd, 1) != b"": return "UNKNOWN"
        if len(raw) == 1:
            return CATEGORIES[raw[0]] if raw[0] < len(CATEGORIES) else "UNKNOWN"
        index = raw[0] - len(CATEGORIES)
        if not 0 <= index < len(PRIVATE_CATEGORIES): return "UNKNOWN"
        if any(code >= len(table) for code, table in zip(raw[1:], TABLES)): return "UNKNOWN"
        value = {field: table[code] for field, table, code in zip(FIELDS, TABLES, raw[1:])}
        value["category"] = PRIVATE_CATEGORIES[index]
        return value if _private_frame(value) == raw else "UNKNOWN"
    except OSError:
        return "UNKNOWN"
    finally:
        discard(process)
