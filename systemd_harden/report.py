"""What the probe tells you: a drop-in file, a table for people and JSON for scripts."""

from __future__ import annotations

import json

from . import __version__
from .probe import ACCEPTED, DROPPED, REJECTED, SKIPPED, Result

_ORDER = {ACCEPTED: 0, DROPPED: 1, REJECTED: 2, SKIPPED: 3}


def _cut(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def render_dropin(result: Result) -> str:
    unit = result.unit
    out = [
        f"# Written by systemd-harden {__version__} for {unit} (systemd {result.systemd_version}).",
        "# Every directive below was applied to the running service, which was restarted and then passed its",
        "# health check. Nothing here is a promise about code paths the health check does not exercise.",
        f"# Install it as /etc/systemd/system/{unit}.d/10-hardening.conf and run:",
        f"#   systemctl daemon-reload && systemctl restart {unit}",
    ]
    unused = [t for t in result.trials if t.status in (REJECTED, DROPPED)]
    if unused:
        out.append("#")
        out.append("# Tried and not used:")
        for t in unused:
            out.append(f"#   {' / '.join(t.lines)}: {_cut(t.reason, 150)}")
    out.append("[Service]")
    out.extend(result.lines())
    return "\n".join(out) + "\n"


def render_summary(result: Result) -> str:
    rows = sorted(result.trials, key=lambda t: _ORDER[t.status])
    kind_w = max((len(t.status) for t in rows), default=8)
    key_w = max((len(t.key) for t in rows), default=10)
    out = [f"{result.unit} on systemd {result.systemd_version}", ""]
    for t in rows:
        value = " ".join(t.lines)
        detail = value if t.status == ACCEPTED else f"{value}: {t.reason}"
        out.append(f"  {t.status:<{kind_w}}  {t.key:<{key_w}}  {_cut(detail, 170)}")
        if t.hint and t.status in (REJECTED, DROPPED):
            out.append(f"  {'':<{kind_w}}  {'':<{key_w}}  likely: {t.hint}")
    kept = len(result.final)
    out.append("")
    out.append(f"{kept} of {len({t.key for t in result.trials})} directives kept.")
    if result.exposure_before is not None and result.exposure_after is not None:
        out.append(
            f"Exposure level by systemd-analyze security (lower is better): {result.exposure_before:g} before, {result.exposure_after:g} with the drop-in."
        )
    if not result.final_ok:
        out.append(f"WARNING: the final set did not hold up: {result.final_reason}")
    out.append(
        f"The service was restarted {result.restarts} times and is back as it was."
        if not result.restore_error
        else f"WARNING: {result.restore_error}"
    )
    return "\n".join(out) + "\n"


def render_json(result: Result) -> str:
    return json.dumps(result.to_json(), indent=2, sort_keys=True) + "\n"
