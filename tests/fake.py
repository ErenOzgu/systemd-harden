"""A simulated machine: a service whose behaviour depends on the drop-in it is given."""

from __future__ import annotations

from dataclasses import dataclass

from systemd_harden.system import Run, UnitState


@dataclass
class Break:
    """How a directive line breaks the service."""

    kind: str  # "start" (restart fails), "crash" (dies after the start), "check" (health check fails), "hang"
    text: str = ""


class FakeSystem:
    def __init__(
        self,
        *,
        breaks: dict[str, Break] | None = None,
        conflicts: list[tuple[str, str]] | None = None,
        version: int = 255,
        root: bool = True,
        systemd: bool = True,
        loaded: bool = True,
        active: bool = True,
        baseline: Break | None = None,
        unknown: set[str] | None = None,
        overridden: dict[str, str] | None = None,
        exposure: bool = True,
        flaky_final: bool = False,
        restore_fails: bool = False,
        reload_fails: bool = False,
        interrupt_after_restarts: int | None = None,
    ) -> None:
        self.breaks = breaks or {}
        self.conflicts = conflicts or []
        self._version = version
        self.root = root
        self.systemd = systemd
        self.loaded = loaded
        self.active = active
        self.baseline = baseline
        self.unknown = unknown or set()
        self.overridden = overridden or {}
        self.has_exposure = exposure
        self.flaky_final = flaky_final
        self.restore_fails = restore_fails
        self.reload_fails = reload_fails
        self.interrupt_after_restarts = interrupt_after_restarts
        self.clock = 1_700_000_000.0
        self.dropin: str | None = None
        self.loaded_dropin: str | None = None
        self.restarts = 0
        self.stops = 0
        self.calls: list[str] = []
        self.checks_run = 0
        self._outcome: Break | None = None
        self._running = active
        self.leftovers: list[str] = []

    # ---- the behaviour of the simulated service ----

    def _lines(self) -> list[str]:
        if not self.loaded_dropin:
            return []
        return [ln for ln in self.loaded_dropin.splitlines() if "=" in ln and not ln.startswith(("#", "["))]

    def _compute(self) -> Break | None:
        lines = self._lines()
        if not lines and self.baseline:
            return self.baseline
        for line in lines:
            if line in self.breaks:
                return self.breaks[line]
        for a, b in self.conflicts:
            if a in lines and b in lines:
                return Break("check", f"{a} and {b} do not work together")
        return None

    # ---- the System protocol ----

    def is_systemd(self) -> bool:
        return self.systemd

    def is_root(self) -> bool:
        return self.root

    def version(self) -> int:
        return self._version

    def unit_state(self, unit: str) -> UnitState:
        if not self.loaded:
            return UnitState(load="not-found")
        out = self._outcome
        if not self._running:
            return UnitState(load="loaded", active="inactive", sub="dead")
        if out is not None and out.kind == "crash":
            return UnitState(load="loaded", active="failed", sub="failed", result="signal", main_status="31")
        if out is not None and out.kind == "loop":
            return UnitState(load="loaded", active="active", sub="running", result="success", restarts=3)
        return UnitState(load="loaded", active="active", sub="running")

    def show_value(self, unit: str, prop: str) -> str | None:
        if prop in self.unknown:
            return None
        if prop in self.overridden:
            return self.overridden[prop]
        for line in self._lines():
            key, _, value = line.partition("=")
            if key == prop:
                return value
        return ""

    def write_dropin(self, unit: str, text: str) -> None:
        self.calls.append("write")
        self.dropin = text

    def remove_dropin(self, unit: str) -> bool:
        self.calls.append("remove")
        existed = self.dropin is not None
        self.dropin = None
        return existed

    def leftover_dropins(self) -> list[str]:
        return list(self.leftovers)

    def daemon_reload(self) -> Run:
        self.calls.append("reload")
        if self.reload_fails:
            return Run(1, "Failed to reload daemon")
        self.loaded_dropin = self.dropin
        return Run(0, "")

    def _begin(self) -> Break | None:
        self.restarts += 1
        if self.interrupt_after_restarts is not None and self.restarts > self.interrupt_after_restarts:
            raise KeyboardInterrupt
        self._outcome = self._compute()
        if self.flaky_final and self.loaded_dropin and self.restarts % 2 == 0 and self.checks_run > 3:
            self._outcome = Break("check", "random failure")
        self._running = True
        return self._outcome

    def restart(self, unit: str, timeout: float) -> Run:
        self.calls.append("restart")
        if self.restore_fails and self.dropin is None and self.restarts >= 1:
            self.restarts += 1
            return Run(1, "Job for demo.service failed")
        out = self._begin()
        if out is not None and out.kind == "start":
            self._running = False
            return Run(1, out.text)
        if out is not None and out.kind == "start-hang":
            self._running = False
            return Run(124, "", timed_out=True)
        return Run(0, "")

    def start(self, unit: str, timeout: float) -> Run:
        return self.restart(unit, timeout)

    def stop(self, unit: str, timeout: float) -> Run:
        self.calls.append("stop")
        self.stops += 1
        self._running = False
        return Run(0, "")

    def journal(self, unit: str, since: float) -> str:
        out = self._outcome
        if out is None:
            return ""
        return out.text

    def run_check(self, argv: tuple[str, ...], timeout: float) -> Run:
        self.checks_run += 1
        out = self._outcome
        if out is not None and out.kind == "check":
            return Run(1, out.text)
        if out is not None and out.kind == "hang":
            return Run(124, "", timed_out=True)
        return Run(0, "ok")

    def exposure(self, unit: str) -> float | None:
        if not self.has_exposure:
            return None
        return round(9.6 - 0.2 * len(self._lines()), 1)

    def now(self) -> float:
        return self.clock

    def sleep(self, seconds: float) -> None:
        self.clock += seconds
