#!/usr/bin/python3
"""A tiny TCP service for trying systemd-harden.

  service.py serve [--port N]                      listen on 127.0.0.1 and answer feature requests
  service.py check FEATURE[,FEATURE...] [--port N]  ask a running service; exit 0 only when every feature works

A request is one line of comma-separated feature names. The reply is "ok" or "fail <feature>: <error>". Every
feature uses one thing that a sandboxing directive can take away, so the features a health check asks for decide
which directives the service survives.
"""

from __future__ import annotations

import ctypes
import mmap
import os
import signal
import socket
import sys
import time

HOME_FILE = os.environ.get("SDH_HOME_FILE", "/home/sdh-demo/data")
VAR_DIR = "/var/lib/sdh-demo"
DEFAULT_PORT = 18765


def feature_ping() -> None:
    """Needs nothing."""


def feature_tmp() -> None:
    """A private /tmp is fine: it writes and reads back within one request."""
    path = f"/tmp/sdh-demo-{os.getpid()}"
    with open(path, "w") as fh:
        fh.write("x")
    with open(path) as fh:
        assert fh.read() == "x"
    os.unlink(path)


def feature_home() -> None:
    """Reads a file under /home (ProtectHome=yes hides it, read-only keeps it readable)."""
    with open(HOME_FILE) as fh:
        fh.read()


def feature_var() -> None:
    """Writes under /var/lib (ProtectSystem=strict makes it read-only, full does not)."""
    path = os.path.join(VAR_DIR, "state")
    with open(path, "w") as fh:
        fh.write("1")
    os.unlink(path)


def feature_etc() -> None:
    """Writes under /etc (ProtectSystem=full and strict make it read-only)."""
    path = "/etc/sdh-demo-probe"
    with open(path, "w") as fh:
        fh.write("1")
    os.unlink(path)


def feature_exec_memory() -> None:
    """Maps memory that is writable and executable (MemoryDenyWriteExecute=yes refuses it)."""
    m = mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
    m.close()


def feature_netlink() -> None:
    """Opens a netlink socket (RestrictAddressFamilies without AF_NETLINK refuses it)."""
    socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0).close()


def feature_namespace() -> None:
    """Creates a UTS namespace in a child process (RestrictNamespaces=yes and a missing CAP_SYS_ADMIN refuse it)."""
    pid = os.fork()
    if pid == 0:
        rc = ctypes.CDLL(None, use_errno=True).unshare(0x04000000)
        os._exit(0 if rc == 0 else 1)
    _, status = os.waitpid(pid, 0)
    if os.waitstatus_to_exitcode(status) != 0:
        raise PermissionError("unshare(CLONE_NEWUTS) failed")


def feature_sysctl() -> None:
    """Writes a kernel setting back unchanged (ProtectKernelTunables=yes makes /proc/sys read-only)."""
    with open("/proc/sys/vm/swappiness", "r+") as fh:
        value = fh.read()
        fh.seek(0)
        fh.write(value)


FEATURES = {
    "ping": feature_ping,
    "tmp": feature_tmp,
    "home": feature_home,
    "var": feature_var,
    "etc": feature_etc,
    "exec-memory": feature_exec_memory,
    "netlink": feature_netlink,
    "namespace": feature_namespace,
    "sysctl": feature_sysctl,
}


def answer(request: str) -> str:
    for name in (n.strip() for n in request.split(",") if n.strip()):
        func = FEATURES.get(name)
        if func is None:
            return f"fail {name}: unknown feature"
        try:
            func()
        except Exception as exc:
            return f"fail {name}: {type(exc).__name__}: {exc}"
    return "ok"


def serve(port: int) -> int:
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(8)
    print(f"listening on 127.0.0.1:{port}", flush=True)
    while True:
        conn, _ = srv.accept()
        with conn:
            conn.settimeout(5)
            try:
                line = conn.makefile("r").readline(1024)
                conn.sendall((answer(line) + "\n").encode())
            except OSError:
                pass


def check(features: str, port: int) -> int:
    deadline = time.time() + 2
    while True:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=5) as conn:
                conn.sendall((features + "\n").encode())
                reply = conn.makefile("r").readline().strip()
            break
        except OSError as exc:
            if time.time() > deadline:
                print(f"cannot reach the service: {exc}")
                return 2
            time.sleep(0.1)
    print(reply)
    return 0 if reply == "ok" else 1


def main(argv: list[str]) -> int:
    port = DEFAULT_PORT
    if "--port" in argv:
        i = argv.index("--port")
        port = int(argv[i + 1])
        del argv[i : i + 2]
    if len(argv) == 1 and argv[0] == "serve":
        return serve(port)
    if len(argv) == 2 and argv[0] == "check":
        return check(argv[1], port)
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
