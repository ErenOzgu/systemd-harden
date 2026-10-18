"""RealSystem against stand-in systemctl, journalctl and systemd-analyze, so the parsing is tested without systemd."""

import os
import stat

import pytest

from systemd_harden.system import DROPIN_NAME, RealSystem

STUB = """#!/bin/sh
# records its arguments, then prints what the test asked for
echo "$(basename "$0") $*" >> "$STUB_LOG"
case "$(basename "$0") $1" in
  "systemctl --version") printf 'systemd 249 (249.11-0ubuntu3.12)\\n+PAM +AUDIT\\n' ;;
  "systemctl show") cat "$STUB_SHOW" ;;
  "journalctl -u") printf 'Main process exited, code=killed, status=31/SYS\\n' ;;
  "systemd-analyze security") cat "$STUB_ANALYZE" ;;
  "systemctl restart") exit "${STUB_RESTART_RC:-0}" ;;
esac
"""


@pytest.fixture
def stubs(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for name in ("systemctl", "journalctl", "systemd-analyze"):
        path = bindir / name
        path.write_text(STUB)
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
    log = tmp_path / "log"
    show = tmp_path / "show"
    analyze = tmp_path / "analyze"
    for f in (log, show, analyze):
        f.write_text("")
    monkeypatch.setenv("PATH", f"{bindir}:{os.environ['PATH']}")
    monkeypatch.setenv("STUB_LOG", str(log))
    monkeypatch.setenv("STUB_SHOW", str(show))
    monkeypatch.setenv("STUB_ANALYZE", str(analyze))

    class S:
        pass

    s = S()
    s.log, s.show, s.analyze = log, show, analyze
    s.system = RealSystem(run_dir=tmp_path / "run")
    s.run_dir = tmp_path / "run"
    return s


def test_the_version_is_read_from_the_first_line(stubs):
    assert stubs.system.version() == 249


def test_the_version_is_zero_when_it_cannot_be_read(stubs, monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", str(tmp_path / "nothing"))
    assert stubs.system.version() == 0


def test_unit_state_is_parsed(stubs):
    stubs.show.write_text(
        "LoadState=loaded\nActiveState=failed\nSubState=failed\nResult=signal\nNRestarts=3\nExecMainStatus=31\n"
    )
    st = stubs.system.unit_state("demo.service")
    assert (st.load, st.active, st.sub, st.result, st.restarts, st.main_status) == (
        "loaded",
        "failed",
        "failed",
        "signal",
        3,
        "31",
    )
    assert "systemctl show demo.service --no-pager -p LoadState -p ActiveState" in stubs.log.read_text()


def test_unit_state_copes_with_old_systemd_and_garbage(stubs):
    stubs.show.write_text(
        "LoadState=loaded\nActiveState=active\nSubState=running\nResult=success\nNRestarts=lots\n"
    )
    st = stubs.system.unit_state("demo.service")
    assert st.restarts == 0 and st.main_status == "0"
    stubs.show.write_text("")
    assert stubs.system.unit_state("demo.service").load == "not-found"


def test_show_value(stubs):
    stubs.show.write_text("ProtectSystem=strict\n")
    assert stubs.system.show_value("demo.service", "ProtectSystem") == "strict"
    assert stubs.system.show_value("demo.service", "ProtectHome") is None
    stubs.show.write_text("ProtectSystem=\n")
    assert stubs.system.show_value("demo.service", "ProtectSystem") == ""


def test_restart_clears_the_failed_state_and_the_start_limit_first(stubs):
    stubs.system.restart("demo.service", 5)
    calls = stubs.log.read_text().splitlines()
    assert calls == ["systemctl reset-failed demo.service", "systemctl restart demo.service"]


def test_restart_reports_the_exit_status(stubs, monkeypatch):
    monkeypatch.setenv("STUB_RESTART_RC", "1")
    assert stubs.system.restart("demo.service", 5).rc == 1


def test_the_journal_is_asked_for_the_unit_since_the_start(stubs):
    out = stubs.system.journal("demo.service", 1700000000.7)
    assert "status=31/SYS" in out
    assert "journalctl -u demo.service --no-pager -o cat -n 60 --since @1700000000" in stubs.log.read_text()


@pytest.mark.parametrize(
    "text, score",
    [
        ("NAME  DESCRIPTION  EXPOSURE\n→ Overall exposure level for demo.service: 9.6 UNSAFE 😨\n", 9.6),
        ("→ Overall exposure level for demo.service: 2.1 OK 🙂\n", 2.1),
        ("→ Overall exposure level for demo.service: 10 UNSAFE\n", 10.0),
        ("something else entirely\n", None),
        ("", None),
    ],
)
def test_exposure_is_read_from_systemd_analyze(stubs, text, score):
    stubs.analyze.write_text(text)
    assert stubs.system.exposure("demo.service") == score


def test_the_drop_in_is_written_atomically_world_readable_and_removed(stubs):
    stubs.system.write_dropin("demo.service", "[Service]\nUMask=0077\n")
    path = stubs.run_dir / "demo.service.d" / DROPIN_NAME
    assert path.read_text() == "[Service]\nUMask=0077\n"
    assert stat.S_IMODE(path.stat().st_mode) == 0o644
    assert not list(path.parent.glob("*.tmp"))
    stubs.system.write_dropin("demo.service", "[Service]\nUMask=0027\n")
    assert path.read_text().endswith("0027\n")
    assert stubs.system.leftover_dropins() == ["demo.service"]
    assert stubs.system.remove_dropin("demo.service") is True
    assert not path.parent.exists()
    assert stubs.system.remove_dropin("demo.service") is False
    assert stubs.system.leftover_dropins() == []


def test_removing_the_drop_in_leaves_other_drop_ins_alone(stubs):
    stubs.system.write_dropin("demo.service", "[Service]\nUMask=0077\n")
    other = stubs.run_dir / "demo.service.d" / "10-mine.conf"
    other.write_text("[Service]\nEnvironment=A=b\n")
    stubs.system.remove_dropin("demo.service")
    assert other.exists()
    assert not (stubs.run_dir / "demo.service.d" / DROPIN_NAME).exists()


def test_leftovers_of_several_units_are_found_in_order(stubs):
    for unit in ("b.service", "a.service"):
        stubs.system.write_dropin(unit, "[Service]\n")
    (stubs.run_dir / "c.service.d").mkdir()
    (stubs.run_dir / "c.service.d" / "10-mine.conf").write_text("")
    assert stubs.system.leftover_dropins() == ["a.service", "b.service"]


def test_a_check_that_takes_too_long_is_cut_off(stubs):
    r = stubs.system.run_check(("sleep", "5"), 0.3)
    assert r.timed_out and r.rc == 124


def test_a_check_that_does_not_exist_is_reported_not_raised(stubs):
    r = stubs.system.run_check(("/nonexistent/check",), 5)
    assert r.rc == 127 and "nonexistent" in r.out


def test_the_check_sees_the_callers_environment_but_systemctl_gets_a_clean_one(stubs, monkeypatch):
    monkeypatch.delenv("LC_ALL", raising=False)
    monkeypatch.setenv("MY_TOKEN", "abc")
    out = stubs.system.run_check(("sh", "-c", "echo ${LC_ALL-unset} $MY_TOKEN"), 5).out
    assert out.strip() == "unset abc"


def test_the_check_has_no_input_and_its_output_is_merged(stubs):
    out = stubs.system.run_check(("sh", "-c", "cat; echo out; echo err >&2; exit 3"), 5)
    assert out.rc == 3 and out.out.split() == ["out", "err"]


def test_huge_output_is_cut(stubs):
    r = stubs.system.run_check(("sh", "-c", "head -c 100000 /dev/zero | tr '\\0' x"), 5)
    assert len(r.out) == 20000


def test_binary_output_does_not_break_decoding(stubs):
    r = stubs.system.run_check(("sh", "-c", "printf '\\377\\376ok'"), 5)
    assert r.out.endswith("ok")
