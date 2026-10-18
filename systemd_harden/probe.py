"""The probe: baseline, one directive at a time, the survivors together, a final check, and put everything back.

Every step is the same experiment: write a drop-in under /run, reload, restart the unit, wait a moment, ask
systemd whether it is still running, and run the user's health check. A directive is only kept when that
experiment succeeds.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field

from .catalogue import CATALOGUE, Candidate, Directive
from .diagnose import hint, short
from .system import System, UnitState

ACCEPTED = "accepted"
REJECTED = "rejected"
SKIPPED = "skipped"
DROPPED = "dropped"

# Directives whose value `systemctl show` reports back as a single word, so that "the directive is really in
# effect" can be checked. Anything else is trusted to be applied when the drop-in is.
SCALAR_KEYS = frozenset(
    {
        "NoNewPrivileges",
        "PrivateTmp",
        "ProtectSystem",
        "ProtectHome",
        "PrivateDevices",
        "DevicePolicy",
        "ProtectKernelTunables",
        "ProtectKernelModules",
        "ProtectKernelLogs",
        "ProtectControlGroups",
        "ProtectClock",
        "ProtectHostname",
        "ProtectProc",
        "ProcSubset",
        "RestrictSUIDSGID",
        "RestrictRealtime",
        "RestrictNamespaces",
        "LockPersonality",
        "MemoryDenyWriteExecute",
        "RemoveIPC",
        "SystemCallArchitectures",
        "PrivateUsers",
        "PrivateNetwork",
        "KeyringMode",
        "UMask",
    }
)

CRITICAL = re.compile(
    r"^(systemd-.*|dbus.*|ssh.*|sshd.*|getty@.*|serial-getty@.*|user@.*|user-runtime-dir@.*|polkit.*|"
    r"NetworkManager.*|docker.*|containerd.*|snapd.*)\.service$"
)
UNIT_NAME = re.compile(r"^[A-Za-z0-9:_.@\\-]{1,200}\.service$")


class Refusal(Exception):
    """The probe will not start. `code` is the exit status the command line should use."""

    def __init__(self, message: str, code: int = 3) -> None:
        super().__init__(message)
        self.code = code


class BaselineFailed(Exception):
    def __init__(self, reason: str, diagnosis: str) -> None:
        super().__init__(reason)
        self.reason = reason
        self.diagnosis = diagnosis


@dataclass(frozen=True)
class Settings:
    check: tuple[str, ...]
    settle: float = 1.5
    check_timeout: float = 30.0
    start_timeout: float = 90.0
    rounds: int = 2
    oneshot: bool = False
    only: tuple[str, ...] = ()
    skip: tuple[str, ...] = ()


@dataclass
class Trial:
    key: str
    lines: tuple[str, ...]
    status: str
    reason: str = ""
    hint: str = ""

    def to_json(self) -> dict:
        return {
            "directive": self.key,
            "lines": list(self.lines),
            "status": self.status,
            "reason": self.reason,
            "hint": self.hint,
        }


@dataclass
class Result:
    unit: str
    systemd_version: int
    trials: list[Trial] = field(default_factory=list)
    final: list[Trial] = field(default_factory=list)
    final_ok: bool = True
    final_reason: str = ""
    exposure_before: float | None = None
    exposure_after: float | None = None
    restarts: int = 0
    restore_error: str = ""

    def lines(self) -> list[str]:
        """The `[Service]` lines of the drop-in, in catalogue order."""
        return [line for trial in self.final for line in trial.lines]

    def to_json(self) -> dict:
        return {
            "unit": self.unit,
            "systemd_version": self.systemd_version,
            "directives": [t.to_json() for t in self.trials],
            "dropin": self.lines(),
            "final_ok": self.final_ok,
            "final_reason": self.final_reason,
            "exposure_before": self.exposure_before,
            "exposure_after": self.exposure_after,
            "restarts": self.restarts,
            "restore_error": self.restore_error,
        }


def dropin_text(lines: list[str]) -> str:
    return "[Service]\n" + "".join(f"{line}\n" for line in lines)


class Prober:
    def __init__(
        self, system: System, unit: str, settings: Settings, log: Callable[[str], None] = lambda _m: None
    ) -> None:
        self.system = system
        self.unit = unit
        self.settings = settings
        self.log = log
        self.restarts = 0

    # ---- one experiment ----

    def _apply(self, lines: list[str]) -> None:
        """Make `lines` the only thing the probe drop-in says (nothing at all when empty)."""
        if lines:
            self.system.write_dropin(self.unit, dropin_text(lines))
        else:
            self.system.remove_dropin(self.unit)
        reload = self.system.daemon_reload()
        if reload.rc != 0:
            raise Refusal(f"systemctl daemon-reload failed: {short(reload.out)}")

    def _state_problem(self, st: UnitState, when: str) -> str:
        if self.settings.oneshot:
            return ""
        if st.active != "active":
            return f"the service is {st.active}/{st.sub} (result {st.result}, exit status {st.main_status}) {when}"
        if st.result != "success" or st.restarts > 0:
            return f"the service was restarted by systemd {when} (result {st.result}, {st.restarts} automatic restarts)"
        return ""

    def experiment(self) -> tuple[bool, str, str]:
        """Restart, settle, look, check. Returns (ok, reason, hint)."""
        s = self.settings
        started = self.system.now()
        self.restarts += 1
        run = self.system.restart(self.unit, s.start_timeout)
        if run.rc != 0:
            reason = "the service did not start" + (": " + short(run.out) if run.out.strip() else "")
            if run.timed_out:
                reason = f"the service did not finish starting within {s.start_timeout:g} s"
            return False, reason, hint(run.out, self.system.journal(self.unit, started))
        self.system.sleep(s.settle)
        problem = self._state_problem(self.system.unit_state(self.unit), f"{s.settle:g} s after the start")
        if problem:
            return False, problem, hint(self.system.journal(self.unit, started))
        check = self.system.run_check(s.check, s.check_timeout)
        if check.timed_out:
            return (
                False,
                f"the health check did not finish within {s.check_timeout:g} s",
                hint(check.out, self.system.journal(self.unit, started)),
            )
        if check.rc != 0:
            detail = short(check.out)
            reason = f"the health check failed (exit status {check.rc})" + (f": {detail}" if detail else "")
            return False, reason, hint(check.out, self.system.journal(self.unit, started))
        problem = self._state_problem(self.system.unit_state(self.unit), "while the health check ran")
        if problem:
            return False, problem, hint(self.system.journal(self.unit, started))
        return True, "", ""

    def try_lines(self, lines: list[str]) -> tuple[bool, str, str]:
        self._apply(lines)
        return self.experiment()

    # ---- is the directive in effect? ----

    def _not_in_effect(self, cand: Candidate) -> str:
        for line in cand.lines:
            key, _, value = line.partition("=")
            if key not in SCALAR_KEYS:
                continue
            shown = self.system.show_value(self.unit, key)
            if shown is None:
                return f"this systemd does not report {key}, so it does not know the directive"
            if shown.lower() != value.lower():
                return (
                    f"systemd reports {key}={shown} instead of {value}: another drop-in or the unit file wins"
                )
        return ""

    # ---- the stages ----

    def _single(self, directive: Directive, version: int) -> list[Trial]:
        """Try the candidates strongest first. Every one that was tried is reported; the last one may be accepted."""
        tried: list[Trial] = []
        for cand in directive.candidates:
            if cand.since > version:
                tried.append(
                    Trial(
                        directive.key, cand.lines, SKIPPED, f"needs systemd {cand.since}, this is {version}"
                    )
                )
                continue
            self._apply(list(cand.lines))
            problem = self._not_in_effect(cand)
            if problem:
                tried.append(Trial(directive.key, cand.lines, SKIPPED, problem))
                continue
            ok, reason, why = self.experiment()
            if ok:
                tried.append(Trial(directive.key, cand.lines, ACCEPTED))
                break
            tried.append(Trial(directive.key, cand.lines, REJECTED, reason, why))
        return tried

    def run(self, version: int) -> Result:
        s = self.settings
        result = Result(unit=self.unit, systemd_version=version)

        # 1. The service must be healthy before anything is changed, or no result means anything.
        ok, reason, why = self.try_lines([])
        if not ok:
            raise BaselineFailed(reason, why)
        result.exposure_before = self.system.exposure(self.unit)

        # 2. One directive at a time, strongest setting first.
        for directive in CATALOGUE:
            if s.only and directive.key not in s.only:
                continue
            if directive.key in s.skip:
                result.trials.append(
                    Trial(directive.key, directive.candidates[0].lines, SKIPPED, "left out with --skip")
                )
                continue
            self.log(f"trying {directive.key}")
            for trial in self._single(directive, version):
                result.trials.append(trial)
                self.log(
                    f"  {' '.join(trial.lines)}: {trial.status}"
                    + (f": {trial.reason}" if trial.reason else "")
                )

        # 3. The survivors together; when they do not work together, add them one by one and drop the ones that
        #    break the set.
        survivors = [t for t in result.trials if t.status == ACCEPTED]
        keep: list[Trial] = []
        if survivors:
            self.log("trying the accepted directives together")
            ok, reason, why = self.try_lines([ln for t in survivors for ln in t.lines])
            if ok:
                keep = survivors
            else:
                self.log(f"  together: {reason}; adding them one by one")
                for t in survivors:
                    ok, reason, why = self.try_lines([ln for k in keep + [t] for ln in k.lines])
                    if ok:
                        keep.append(t)
                    else:
                        t.status = DROPPED
                        t.reason = f"works alone, but not together with the ones before it: {reason}"
                        t.hint = why
        result.final = keep

        # 4. The final set, checked again.
        if keep:
            self._apply(result.lines())
            for round_no in range(1, s.rounds + 1):
                self.log(f"final check {round_no} of {s.rounds}")
                ok, reason, why = self.experiment()
                if not ok:
                    result.final_ok = False
                    result.final_reason = f"final check {round_no}: {reason}"
                    break
            result.exposure_after = self.system.exposure(self.unit)
        else:
            result.exposure_after = result.exposure_before
        result.restarts = self.restarts
        return result


def _preflight(
    system: System, unit: str, settings: Settings, *, allow_restart: bool, allow_critical: bool, what: str
) -> UnitState:
    if not UNIT_NAME.match(unit):
        raise Refusal(f"{unit!r} is not a service unit name such as demo.service", 2)
    if not settings.check:
        raise Refusal("a health check command is required (--check)", 2)
    if not allow_restart:
        raise Refusal(
            f"{what} restarts {unit} many times and changes nothing permanent, but the service is unavailable "
            "while it restarts. Run it on a test machine or in a maintenance window, and pass --allow-restart.",
            2,
        )
    if CRITICAL.match(unit) and not allow_critical:
        raise Refusal(
            f"{unit} looks like a unit the machine depends on (ssh, dbus, systemd itself, ...); pass --allow-critical if you really mean it",
            2,
        )
    if not system.is_systemd():
        raise Refusal("systemd is not the running init system here (no /run/systemd/system)")
    if not system.is_root():
        raise Refusal(
            "run it as root: it writes a drop-in under /run/systemd/system and restarts the service"
        )
    state = system.unit_state(unit)
    if state.load != "loaded":
        raise Refusal(f"{unit} is not loaded (LoadState={state.load})")
    return state


def _restore(system: System, unit: str, was_active: bool, timeout: float) -> str:
    """No drop-in, and the service running again if it was running before. Returns an error text or ''."""
    try:
        system.remove_dropin(unit)
        system.daemon_reload()
        run = system.restart(unit, timeout) if was_active else system.stop(unit, timeout)
        if run.rc != 0:
            return f"could not put {unit} back as it was: {short(run.out)}"
    except Exception as exc:  # restoring must not hide the original failure
        return f"could not put {unit} back as it was: {exc}"
    return ""


def probe(
    system: System,
    unit: str,
    settings: Settings,
    *,
    allow_restart: bool,
    allow_critical: bool = False,
    log: Callable[[str], None] = lambda _m: None,
) -> Result:
    state = _preflight(
        system, unit, settings, allow_restart=allow_restart, allow_critical=allow_critical, what="probing"
    )
    version = system.version()
    if version <= 0:
        raise Refusal("could not read the systemd version from `systemctl --version`")
    was_active = state.active == "active"
    prober = Prober(system, unit, settings, log)
    system.remove_dropin(unit)  # a leftover from a killed run
    try:
        result = prober.run(version)
    except BaseException:
        err = _restore(system, unit, was_active, settings.start_timeout)
        if err:
            log(err)
        raise
    result.restore_error = _restore(system, unit, was_active, settings.start_timeout)
    return result


def verify(
    system: System,
    unit: str,
    lines: list[str],
    settings: Settings,
    *,
    allow_restart: bool,
    allow_critical: bool = False,
) -> tuple[bool, str, str, str]:
    """Apply a given drop-in, restart, check `rounds` times; put everything back.

    Returns (ok, reason, hint, restore_error)."""
    state = _preflight(
        system, unit, settings, allow_restart=allow_restart, allow_critical=allow_critical, what="verifying"
    )
    was_active = state.active == "active"
    prober = Prober(system, unit, settings)
    system.remove_dropin(unit)
    try:
        ok, reason, why = prober.try_lines(lines)
        for _ in range(settings.rounds - 1):
            if not ok:
                break
            ok, reason, why = prober.experiment()
    except BaseException:
        _restore(system, unit, was_active, settings.start_timeout)
        raise
    return ok, reason, why, _restore(system, unit, was_active, settings.start_timeout)
