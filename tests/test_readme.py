"""The README says what the code does: tables and examples are generated from, or compared with, the real thing."""

import io
import re
from contextlib import redirect_stdout
from pathlib import Path

from systemd_harden.catalogue import markdown_table
from systemd_harden.cli import build_parser, main

ROOT = Path(__file__).resolve().parent.parent
README = (ROOT / "README.md").read_text(encoding="utf-8")


def between(start: str, end: str) -> str:
    m = re.search(re.escape(start) + r"(.*?)" + re.escape(end), README, re.S)
    assert m, f"{start} ... {end} not found in the README"
    return m.group(1).strip("\n")


def test_the_directive_table_is_the_one_the_catalogue_generates():
    assert between("<!-- catalogue:start -->", "<!-- catalogue:end -->") == markdown_table()


def test_the_catalogue_command_prints_the_same_table():
    buf = io.StringIO()
    with redirect_stdout(buf):
        assert main(["catalogue", "--markdown"]) == 0
    assert buf.getvalue().rstrip("\n") == markdown_table()


def test_every_include_marker_is_followed_by_the_file():
    found = re.findall(r"<!-- include:(\S+) -->\n```\w*\n(.*?)\n?```", README, re.S)
    assert found, "no include markers"
    for path, block in found:
        assert block.rstrip("\n") == (ROOT / path).read_text(encoding="utf-8").rstrip("\n"), path
    assert {p for p, _ in found} == set(re.findall(r"<!-- include:(\S+) -->", README))


def test_every_option_of_probe_and_verify_is_documented():
    parser = build_parser()
    subs = next(a for a in parser._actions if a.dest == "command").choices
    options = {
        o
        for name in ("probe", "verify")
        for a in subs[name]._actions
        for o in a.option_strings
        if o.startswith("--") and o != "--help"
    }
    table = between("Options of `probe` and `verify`:", "Exit status:")
    for option in sorted(options):
        assert f"`{option}" in table, option


def test_every_command_is_documented():
    parser = build_parser()
    subs = next(a for a in parser._actions if a.dest == "command").choices
    for name in subs:
        assert f"`systemd-harden {name}" in README, name


def test_the_exit_statuses_in_the_readme_are_the_ones_the_code_uses():
    from systemd_harden import cli

    text = between("Exit status:", "## A good health check")
    for code in (
        cli.EXIT_OK,
        cli.EXIT_FAIL,
        cli.EXIT_USAGE,
        cli.EXIT_ENV,
        cli.EXIT_BASELINE,
        cli.EXIT_INTERRUPT,
    ):
        assert re.search(rf"\b{code}\b", text), code


def test_the_readme_says_how_many_directives_there_are():
    from systemd_harden.catalogue import CATALOGUE

    m = re.search(r"(\d+) directives", README)
    # the README need not state a number, but when it does it must be right
    if m:
        assert int(m.group(1)) == len(CATALOGUE)


def test_the_committed_real_run_is_made_of_catalogue_directives():
    from systemd_harden.catalogue import KEYS

    dropin = (ROOT / "examples/demo/real-run/hardening.conf").read_text(encoding="utf-8")
    keys = {ln.split("=", 1)[0] for ln in dropin.splitlines() if ln and not ln.startswith(("#", "["))}
    assert keys
    assert keys <= set(KEYS) | {"ProcSubset", "IPAddressAllow"}, keys - set(KEYS)
    summary = (ROOT / "examples/demo/real-run/summary.txt").read_text(encoding="utf-8")
    accepted = [ln for ln in summary.splitlines() if ln.startswith("  accepted")]
    assert len(accepted) == 27
    assert "27 of 28 directives kept." in summary
