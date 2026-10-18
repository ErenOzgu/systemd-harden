"""Everything that touches the machine: systemctl, journalctl, systemd-analyze, the drop-in file and the health check.

The probe talks to the `System` protocol only, so the whole algorithm can be tested against a simulated service
(tests/fake.py) and run for real on a machine with systemd (RealSystem).
"""

from __future__ import annotations

import os
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

DROPIN_NAME = "zz-systemd-harden-probe.conf"
RUN_DIR = Path("/run/systemd/system")
MAX_OUTPUT = 20000


@dataclass(frozen=True)
class Run:
    rc: int
    out: str
    timed_out: bool = False


@dataclass(frozen=True)
class UnitState:
    load: str = "not-found"
    active: str = "inactive"
    sub: str = "dead"
    result: str = "success"
    restarts: int = 0
    main_status: str = "0"


class System(Protocol):
    def is_systemd(self) -> bool: ...

    def is_root(self) -> bool: ...

    def version(self) -> int: ...

    def unit_state(self, unit: str) -> UnitState: ...

    def show_value(self, unit: str, prop: str) -> str | None: ...

    def write_dropin(self, unit: str, text: str) -> None: ...

    def remove_dropin(self, unit: str) -> bool: ...

    def leftover_dropins(self) -> list[str]: ...

    def daemon_reload(self) -> Run: ...

    def restart(self, unit: str, timeout: float) -> Run: ...

    def start(self, unit: str, timeout: float) -> Run: ...

    def stop(self, unit: str, timeout: float) -> Run: ...

    def journal(self, unit: str, since: float) -> str: ...

    def run_check(self, argv: tuple[str, ...], timeout: float) -> Run: ...

    def exposure(self, unit: str) -> float | None: ...

    def now(self) -> float: ...

    def sleep(self, seconds: float) -> None: ...


_CLEAN_ENV = {"LC_ALL": "C", "SYSTEMD_COLORS": "0", "SYSTEMD_PAGER": "", "SYSTEMD_URLIFY": "0"}


def _decode(data: bytes | str | None) -> str:
    if data is None:
        return ""
    if isinstance(data, bytes):
        data = data.decode("utf-8", "replace")
    return data[-MAX_OUTPUT:]


class RealSystem:
    """The machine this process runs on."""

    def __init__(self, run_dir: Path = RUN_DIR) -> None:
        self.run_dir = run_dir

    # ---- plumbing ----

    def _run(self, argv: list[str], timeout: float, *, clean_env: bool = True) -> Run:
        env = {**os.environ, **_CLEAN_ENV} if clean_env else None
        try:
            proc = subprocess.run(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=timeout,
                env=env,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            return Run(124, _decode(exc.stdout), timed_out=True)
        except OSError as exc:
            return Run(127, f"{argv[0]}: {exc.strerror or exc}")
        return Run(proc.returncode, _decode(proc.stdout))

    # ---- facts ----

    def is_systemd(self) -> bool:
        return os.path.isdir("/run/systemd/system")

    def is_root(self) -> bool:
        return os.geteuid() == 0

    def version(self) -> int:
        out = self._run(["systemctl", "--version"], 10).out
        m = re.match(r"\s*systemd\s+(\d+)", out)
        return int(m.group(1)) if m else 0

    def unit_state(self, unit: str) -> UnitState:
        props = ["LoadState", "ActiveState", "SubState", "Result", "NRestarts", "ExecMainStatus"]
        argv = ["systemctl", "show", unit, "--no-pager"]
        for p in props:
            argv += ["-p", p]
        out = self._run(argv, 20).out
        kv = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
        try:
            restarts = int(kv.get("NRestarts", "0") or 0)
        except ValueError:
            restarts = 0
        return UnitState(
            load=kv.get("LoadState", "not-found"),
            active=kv.get("ActiveState", "inactive"),
            sub=kv.get("SubState", "dead"),
            result=kv.get("Result", "success"),
            restarts=restarts,
            main_status=kv.get("ExecMainStatus", "0"),
        )

    def show_value(self, unit: str, prop: str) -> str | None:
        out = self._run(["systemctl", "show", unit, "--no-pager", "-p", prop], 20).out
        for line in out.splitlines():
            if line.startswith(prop + "="):
                return line[len(prop) + 1 :].strip()
        return None

    # ---- the drop-in ----

    def _dir(self, unit: str) -> Path:
        return self.run_dir / f"{unit}.d"

    def write_dropin(self, unit: str, text: str) -> None:
        d = self._dir(unit)
        d.mkdir(parents=True, exist_ok=True)
        tmp = d / (DROPIN_NAME + ".tmp")
        tmp.write_text(text, encoding="utf-8")
        os.chmod(tmp, 0o644)
        os.replace(tmp, d / DROPIN_NAME)

    def remove_dropin(self, unit: str) -> bool:
        d = self._dir(unit)
        path = d / DROPIN_NAME
        existed = path.exists()
        path.unlink(missing_ok=True)
        (d / (DROPIN_NAME + ".tmp")).unlink(missing_ok=True)
        try:
            d.rmdir()
        except OSError:
            pass  # other drop-ins live there, or it never existed
        return existed

    def leftover_dropins(self) -> list[str]:
        found = []
        for path in sorted(self.run_dir.glob(f"*.d/{DROPIN_NAME}")):
            found.append(path.parent.name[: -len(".d")])
        return found

    # ---- systemctl ----

    def daemon_reload(self) -> Run:
        return self._run(["systemctl", "daemon-reload"], 60)

    def restart(self, unit: str, timeout: float) -> Run:
        self._run(["systemctl", "reset-failed", unit], 20)
        return self._run(["systemctl", "restart", unit], timeout)

    def start(self, unit: str, timeout: float) -> Run:
        self._run(["systemctl", "reset-failed", unit], 20)
        return self._run(["systemctl", "start", unit], timeout)

    def stop(self, unit: str, timeout: float) -> Run:
        return self._run(["systemctl", "stop", unit], timeout)

    def journal(self, unit: str, since: float) -> str:
        argv = ["journalctl", "-u", unit, "--no-pager", "-o", "cat", "-n", "60", "--since", f"@{int(since)}"]
        return self._run(argv, 20).out

    def run_check(self, argv: tuple[str, ...], timeout: float) -> Run:
        return self._run(list(argv), timeout, clean_env=False)

    def exposure(self, unit: str) -> float | None:
        out = self._run(["systemd-analyze", "security", unit, "--no-pager"], 60).out
        m = re.search(r"Overall exposure level for [^:]+:\s+(\d+(?:\.\d+)?)", out)
        return float(m.group(1)) if m else None

    def now(self) -> float:
        return time.time()

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)
