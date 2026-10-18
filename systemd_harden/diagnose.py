"""Turn what a failed start or check left behind into one plain sentence about the likely cause."""

from __future__ import annotations

import re

# Most specific first. Each pattern is matched against the journal and the check output.
_HINTS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"status=31/SYS|killed by SIGSYS|SIGSYS|Bad system call", re.I),
        "a system call was refused by SystemCallFilter, and the kernel killed the process with SIGSYS",
    ),
    (
        re.compile(
            r"status=226/NAMESPACE|Failed to set up mount namespacing|Failed to set up namespace", re.I
        ),
        "systemd could not set up the namespace the directive needs; a path it refers to may be missing",
    ),
    (re.compile(r"status=218/CAPABILITIES", re.I), "the capability set could not be applied to the service"),
    (
        re.compile(r"status=228/SECCOMP|Failed to apply (?:system call|seccomp)", re.I),
        "the seccomp filter could not be installed",
    ),
    (
        re.compile(r"status=217/USER", re.I),
        "the service user could not be set up (check User=, and PrivateUsers=)",
    ),
    (
        re.compile(r"status=203/EXEC", re.I),
        "the program could not be executed in the new environment (a path it needs is hidden?)",
    ),
    (
        re.compile(r"status=200/CHDIR|status=201/NICE|status=225/NETWORK", re.I),
        "an environment step the directive needs failed before the program started",
    ),
    (
        re.compile(r"Read-only file system|EROFS", re.I),
        "the service wrote to a path that is now read-only (ReadWritePaths= or StateDirectory= would allow it)",
    ),
    (
        re.compile(r"Address family not supported|EAFNOSUPPORT", re.I),
        "the service opened a socket family that RestrictAddressFamilies forbids",
    ),
    (
        re.compile(
            r"Network is unreachable|ENETUNREACH|Cannot assign requested address|Connection refused", re.I
        ),
        "the service's network access changed (IPAddressDeny=, PrivateNetwork=)",
    ),
    (re.compile(r"Operation not permitted|EPERM", re.I), "an operation the directive forbids was attempted"),
    (
        re.compile(r"Permission denied|EACCES", re.I),
        "the service was refused access to something (a hidden or read-only path, or a missing capability)",
    ),
    (
        re.compile(r"No such file or directory|ENOENT", re.I),
        "a path the service needs is no longer visible (ProtectHome=, PrivateTmp=, PrivateDevices=, ProtectProc= hide paths)",
    ),
)


def hint(*texts: str) -> str:
    blob = "\n".join(t for t in texts if t)
    for pattern, sentence in _HINTS:
        if pattern.search(blob):
            return sentence
    return ""


def short(text: str, limit: int = 240) -> str:
    """The last few non-empty lines on one line, cut to `limit` characters."""
    lines = [re.sub(r"\s+", " ", ln).strip() for ln in text.splitlines() if ln.strip()]
    joined = " | ".join(lines[-3:])
    if len(joined) > limit:
        joined = "…" + joined[-(limit - 1) :]
    return joined
