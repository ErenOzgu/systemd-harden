from __future__ import annotations

import argparse
import os
import shlex
import signal
import sys
from pathlib import Path

from . import __version__
from .catalogue import CATALOGUE, KEYS, as_json, markdown_table
from .probe import BaselineFailed, Refusal, Settings, probe, verify
from .report import render_dropin, render_json, render_summary
from .system import RealSystem, System

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_USAGE = 2
EXIT_ENV = 3
EXIT_BASELINE = 4
EXIT_INTERRUPT = 130


def _err(message: str) -> None:
    print(f"systemd-harden: {message}", file=sys.stderr)


def _check_argv(text: str) -> tuple[str, ...]:
    try:
        argv = tuple(shlex.split(text))
    except ValueError as exc:
        raise Refusal(f"--check cannot be parsed: {exc}", EXIT_USAGE) from exc
    if not argv:
        raise Refusal("--check is empty", EXIT_USAGE)
    return argv


def _keys(text: str, option: str) -> tuple[str, ...]:
    keys = tuple(k.strip() for k in text.split(",") if k.strip())
    unknown = [k for k in keys if k not in KEYS]
    if unknown:
        raise Refusal(
            f"{option}: unknown directive {', '.join(unknown)} (see `systemd-harden catalogue`)", EXIT_USAGE
        )
    return keys


def _positive(name: str, value: float, *, allow_zero: bool = False) -> float:
    if value < 0 or (value == 0 and not allow_zero):
        raise Refusal(f"{name} must be {'zero or ' if allow_zero else ''}greater than zero", EXIT_USAGE)
    return value


def _settings(a: argparse.Namespace) -> Settings:
    if a.rounds < 1 or a.rounds > 20:
        raise Refusal("--rounds must be between 1 and 20", EXIT_USAGE)
    return Settings(
        check=_check_argv(a.check),
        settle=_positive("--settle", a.settle, allow_zero=True),
        check_timeout=_positive("--check-timeout", a.check_timeout),
        start_timeout=_positive("--start-timeout", a.start_timeout),
        rounds=a.rounds,
        oneshot=a.oneshot,
        only=_keys(a.only, "--only"),
        skip=_keys(a.skip, "--skip"),
    )


def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("unit", help="the service to work on, for example demo.service")
    p.add_argument(
        "--check",
        required=True,
        metavar="COMMAND",
        help="health check: a command that exits 0 while the service works (run without a shell)",
    )
    p.add_argument(
        "--allow-restart", action="store_true", help="say that restarting the service many times is fine"
    )
    p.add_argument("--allow-critical", action="store_true", help="also work on units such as sshd or dbus")
    p.add_argument(
        "--settle",
        type=float,
        default=1.5,
        metavar="SECONDS",
        help="how long a started service must stay up before the check (default 1.5)",
    )
    p.add_argument(
        "--check-timeout",
        type=float,
        default=30.0,
        metavar="SECONDS",
        help="give up on a health check after this long (default 30)",
    )
    p.add_argument(
        "--start-timeout",
        type=float,
        default=90.0,
        metavar="SECONDS",
        help="give up on a restart after this long (default 90)",
    )
    p.add_argument(
        "--rounds", type=int, default=2, help="how often the final set is restarted and checked (default 2)"
    )
    p.add_argument(
        "--oneshot",
        action="store_true",
        help="the service runs and exits (Type=oneshot): do not require it to stay active",
    )
    p.add_argument("--only", default="", metavar="A,B", help="try only these directives")
    p.add_argument("--skip", default="", metavar="A,B", help="do not try these directives")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="systemd-harden",
        description="Find out which systemd sandboxing directives a service survives, and write a drop-in with them.",
    )
    p.add_argument("--version", action="version", version=f"systemd-harden {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    pr = sub.add_parser(
        "probe", help="try the directives on a running service and write the drop-in that survived"
    )
    _add_common(pr)
    pr.add_argument(
        "-o", "--output", metavar="FILE", help="write the drop-in here instead of standard output"
    )
    pr.add_argument("--json", metavar="FILE", help="also write the full result as JSON")
    pr.add_argument("-q", "--quiet", action="store_true", help="no progress lines")

    ve = sub.add_parser(
        "verify", help="check that a drop-in file still lets the service pass its health check"
    )
    _add_common(ve)
    ve.add_argument(
        "--dropin", required=True, metavar="FILE", help="the drop-in to apply (as written by `probe`)"
    )

    cl = sub.add_parser(
        "cleanup", help="remove probe drop-ins that a killed run left under /run/systemd/system"
    )
    cl.add_argument("--dry-run", action="store_true", help="only list them")

    ca = sub.add_parser("catalogue", help="list the directives that are tried, strongest setting first")
    fmt = ca.add_mutually_exclusive_group()
    fmt.add_argument("--markdown", action="store_true", help="print the table used in the README")
    fmt.add_argument(
        "--json", action="store_true", help="print the directives, candidates and `since` versions as JSON"
    )
    return p


def _drop_in_lines(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise Refusal(f"{path}: {exc}", EXIT_USAGE) from exc
    section = ""
    lines: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line
            continue
        if section != "[Service]":
            raise Refusal(f"{path}: only a [Service] section is accepted, found {line!r}", EXIT_USAGE)
        if "=" not in line:
            raise Refusal(f"{path}: not a Key=Value line: {line!r}", EXIT_USAGE)
        lines.append(line)
    return lines


def _cmd_catalogue(a: argparse.Namespace) -> int:
    if a.markdown:
        print(markdown_table())
        return EXIT_OK
    if a.json:
        print(as_json())
        return EXIT_OK
    for d in CATALOGUE:
        print(f"{d.key}: {d.why}")
        for c in d.candidates:
            print(f"    {' + '.join(c.lines)}   (systemd {c.since}+)")
    return EXIT_OK


def _cmd_cleanup(system: System, a: argparse.Namespace) -> int:
    if not system.is_systemd():
        raise Refusal("systemd is not the running init system here (no /run/systemd/system)")
    if not system.is_root():
        raise Refusal("run it as root")
    units = system.leftover_dropins()
    if not units:
        print("no leftover probe drop-ins")
        return EXIT_OK
    for unit in units:
        if a.dry_run:
            print(f"would remove the probe drop-in of {unit}")
            continue
        system.remove_dropin(unit)
        print(
            f"removed the probe drop-in of {unit}; restart it to drop the settings: systemctl restart {unit}"
        )
    if not a.dry_run:
        system.daemon_reload()
    return EXIT_OK


def _cmd_probe(system: System, a: argparse.Namespace) -> int:
    settings = _settings(a)
    log = (lambda m: None) if a.quiet else (lambda m: print(m, file=sys.stderr))
    try:
        result = probe(
            system, a.unit, settings, allow_restart=a.allow_restart, allow_critical=a.allow_critical, log=log
        )
    except BaselineFailed as exc:
        _err(
            f"{a.unit} does not pass the health check even with no change at all, so there is nothing to compare with: {exc.reason}"
        )
        if exc.diagnosis:
            _err(f"likely: {exc.diagnosis}")
        return EXIT_BASELINE
    print(render_summary(result), file=sys.stderr, end="")
    text = render_dropin(result)
    if a.output:
        Path(a.output).write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    if a.json:
        Path(a.json).write_text(render_json(result), encoding="utf-8")
    return EXIT_OK if result.final_ok and not result.restore_error else EXIT_FAIL


def _cmd_verify(system: System, a: argparse.Namespace) -> int:
    settings = _settings(a)
    lines = _drop_in_lines(Path(a.dropin))
    ok, reason, why, restore_error = verify(
        system, a.unit, lines, settings, allow_restart=a.allow_restart, allow_critical=a.allow_critical
    )
    if restore_error:
        _err(restore_error)
    if ok:
        print(
            f"{a.unit} passes its health check with {a.dropin} ({len(lines)} lines, {settings.rounds} rounds)"
        )
        return EXIT_OK if not restore_error else EXIT_FAIL
    _err(f"{a.unit} does not pass with {a.dropin}: {reason}")
    if why:
        _err(f"likely: {why}")
    return EXIT_FAIL


def main(argv: list[str] | None = None, system: System | None = None) -> int:
    args = build_parser().parse_args(argv)
    system = system or RealSystem()

    def _terminate(_signo: int, _frame: object) -> None:
        raise KeyboardInterrupt

    try:
        if args.command == "catalogue":
            return _cmd_catalogue(args)
        old = signal.signal(signal.SIGTERM, _terminate)
        try:
            if args.command == "cleanup":
                return _cmd_cleanup(system, args)
            if args.command == "probe":
                return _cmd_probe(system, args)
            return _cmd_verify(system, args)
        finally:
            signal.signal(signal.SIGTERM, old)
    except Refusal as exc:
        _err(str(exc))
        return exc.code
    except KeyboardInterrupt:
        _err("interrupted; the probe drop-in was removed and the service restarted")
        return EXIT_INTERRUPT
    except BrokenPipeError:
        # `systemd-harden catalogue | head`: the reader went away, which is not an error.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return EXIT_OK
    except OSError as exc:
        _err(str(exc))
        return EXIT_ENV


if __name__ == "__main__":
    sys.exit(main())
