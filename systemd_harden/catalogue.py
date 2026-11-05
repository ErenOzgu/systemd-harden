"""The directives that are tried, strongest setting first.

Each entry has one or more candidates. A candidate is the exact `[Service]` lines that go into the drop-in.
The strongest candidate is tried first; when it breaks the service the next, weaker one is tried.
`since` is the first systemd version that understands every line of the candidate: an older systemd would
ignore the line with a warning, which would look like a pass, so the directive is skipped there instead.
"""

from __future__ import annotations

import json
from dataclasses import dataclass


@dataclass(frozen=True)
class Candidate:
    lines: tuple[str, ...]
    since: int

    def keys(self) -> tuple[str, ...]:
        return tuple(line.split("=", 1)[0] for line in self.lines)

    @property
    def text(self) -> str:
        return "\n".join(self.lines)


@dataclass(frozen=True)
class Directive:
    key: str
    why: str
    candidates: tuple[Candidate, ...]


def _c(since: int, *lines: str) -> Candidate:
    return Candidate(lines=tuple(lines), since=since)


CATALOGUE: tuple[Directive, ...] = (
    Directive(
        "NoNewPrivileges",
        "The service and its children can never gain privileges through setuid binaries or file capabilities.",
        (_c(187, "NoNewPrivileges=yes"),),
    ),
    Directive(
        "PrivateTmp",
        "The service gets its own /tmp and /var/tmp, invisible to others and cleaned up when it stops.",
        (_c(38, "PrivateTmp=yes"),),
    ),
    Directive(
        "ProtectSystem",
        "The operating system's directories become read-only for the service (strict: the whole file system except /dev, /proc and /sys).",
        (
            _c(214, "ProtectSystem=strict"),
            _c(214, "ProtectSystem=full"),
            _c(214, "ProtectSystem=yes"),
        ),
    ),
    Directive(
        "ProtectHome",
        "/home, /root and /run/user are made inaccessible or read-only.",
        (_c(214, "ProtectHome=yes"), _c(214, "ProtectHome=read-only")),
    ),
    Directive(
        "PrivateDevices",
        "The service sees only the harmless pseudo devices (null, zero, random, ...) in /dev, not disks or hardware.",
        (_c(208, "PrivateDevices=yes"),),
    ),
    Directive(
        "DevicePolicy",
        "Access to device nodes is limited to the usual pseudo devices.",
        (_c(30, "DevicePolicy=closed"),),
    ),
    Directive(
        "ProtectKernelTunables",
        "/proc/sys, /sys and similar kernel knobs are read-only.",
        (_c(232, "ProtectKernelTunables=yes"),),
    ),
    Directive(
        "ProtectKernelModules",
        "The service cannot load or unload kernel modules.",
        (_c(232, "ProtectKernelModules=yes"),),
    ),
    Directive(
        "ProtectKernelLogs",
        "The service cannot read the kernel log ring buffer.",
        (_c(244, "ProtectKernelLogs=yes"),),
    ),
    Directive(
        "ProtectControlGroups",
        "The control group hierarchy is read-only.",
        (_c(232, "ProtectControlGroups=yes"),),
    ),
    Directive(
        "ProtectClock",
        "The service cannot change the system clock or the hardware clock.",
        (_c(245, "ProtectClock=yes"),),
    ),
    Directive(
        "ProtectHostname",
        "The service cannot change the host name.",
        (_c(242, "ProtectHostname=yes"),),
    ),
    Directive(
        "ProtectProc",
        "Other users' processes are hidden in /proc, and only process directories are shown.",
        (_c(247, "ProtectProc=invisible", "ProcSubset=pid"), _c(247, "ProtectProc=invisible")),
    ),
    Directive(
        "RestrictSUIDSGID",
        "The service cannot create files with the set-user-ID or set-group-ID bit.",
        (_c(242, "RestrictSUIDSGID=yes"),),
    ),
    Directive(
        "RestrictRealtime",
        "The service cannot ask for realtime scheduling.",
        (_c(231, "RestrictRealtime=yes"),),
    ),
    Directive(
        "RestrictNamespaces",
        "The service cannot create new namespaces, a common step in container escapes.",
        (_c(233, "RestrictNamespaces=yes"),),
    ),
    Directive(
        "LockPersonality",
        "The service cannot change its execution domain.",
        (_c(235, "LockPersonality=yes"),),
    ),
    Directive(
        "MemoryDenyWriteExecute",
        "Memory cannot be both writable and executable, which stops most injected code.",
        (_c(231, "MemoryDenyWriteExecute=yes"),),
    ),
    Directive(
        "RemoveIPC",
        "The service's System V and POSIX IPC objects are removed when it stops.",
        (_c(211, "RemoveIPC=yes"),),
    ),
    Directive(
        "RestrictAddressFamilies",
        "Only the listed socket families can be opened (first try: Unix sockets only, then Unix plus IPv4 and IPv6).",
        (
            _c(211, "RestrictAddressFamilies=AF_UNIX"),
            _c(211, "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6"),
        ),
    ),
    Directive(
        "SystemCallArchitectures",
        "Only native system calls are allowed, which closes the 32-bit compatibility door on 64-bit machines.",
        (_c(209, "SystemCallArchitectures=native"),),
    ),
    Directive(
        "SystemCallFilter",
        "Only the system calls a normal service needs are allowed (first try also without privileged and resource-control calls).",
        (
            _c(211, "SystemCallFilter=@system-service", "SystemCallFilter=~@privileged @resources"),
            _c(211, "SystemCallFilter=@system-service"),
            _c(211, "SystemCallFilter=~@clock @debug @module @mount @obsolete @raw-io @reboot @swap"),
        ),
    ),
    Directive(
        "CapabilityBoundingSet",
        "The service runs with no Linux capabilities at all (second try: only the one for binding ports below 1024).",
        (
            _c(187, "CapabilityBoundingSet="),
            _c(187, "CapabilityBoundingSet=CAP_NET_BIND_SERVICE"),
        ),
    ),
    Directive(
        "PrivateUsers",
        "The service sees only itself and root in user and group lists, and runs in a user namespace.",
        (_c(232, "PrivateUsers=yes"),),
    ),
    Directive(
        "PrivateNetwork",
        "The service gets an empty network namespace with only a loopback device (it can not be reached from outside).",
        (_c(38, "PrivateNetwork=yes"),),
    ),
    Directive(
        "IPAddressDeny",
        "The service can only talk to the local host (first try) or the local network.",
        (
            _c(235, "IPAddressDeny=any", "IPAddressAllow=localhost"),
            _c(
                235,
                "IPAddressDeny=any",
                "IPAddressAllow=localhost",
                "IPAddressAllow=link-local",
                "IPAddressAllow=multicast",
            ),
        ),
    ),
    Directive(
        "KeyringMode",
        "The service gets its own kernel keyring, not shared with other services.",
        (_c(233, "KeyringMode=private"),),
    ),
    Directive(
        "UMask",
        "Files the service creates are private to its user by default.",
        (_c(30, "UMask=0077"),),
    ),
)

# The order matters twice: single trials run in it, and the greedy combination adds directives in it.
KEYS = tuple(d.key for d in CATALOGUE)


def by_key(key: str) -> Directive:
    for d in CATALOGUE:
        if d.key == key:
            return d
    raise KeyError(key)


def markdown_table() -> str:
    """The README's table of directives."""
    rows = ["| Directive | Tried in this order | What it takes away |", "| --- | --- | --- |"]
    for d in CATALOGUE:
        tries = "<br>".join(f"`{' + '.join(c.lines)}`" for c in d.candidates)
        rows.append(f"| `{d.key}` | {tries} | {d.why} |")
    return "\n".join(rows)


def as_json() -> str:
    """The catalogue as JSON, for tools that want the directives and their `since` versions."""
    data = [
        {
            "key": d.key,
            "why": d.why,
            "candidates": [{"lines": list(c.lines), "since": c.since} for c in d.candidates],
        }
        for d in CATALOGUE
    ]
    return json.dumps(data, indent=2, ensure_ascii=False)
