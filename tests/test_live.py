"""The probe against a real systemd, with the demo service.

These need root and systemd as PID 1, so on an ordinary machine they are skipped. CI runs them on GitHub's Ubuntu
runners with SYSTEMD_HARDEN_REQUIRE_SYSTEMD=1, which turns a skip into a failure.
"""

import json
import os
import subprocess
from pathlib import Path

import pytest

from systemd_harden.cli import main
from systemd_harden.system import DROPIN_NAME, RealSystem

ROOT = Path(__file__).resolve().parent.parent
UNIT = "sdh-demo.service"
CHECK = "/usr/bin/python3 /usr/local/lib/systemd-harden-demo/service.py check {features} --port 18765"

LIVE = hasattr(os, "geteuid") and os.geteuid() == 0 and os.path.isdir("/run/systemd/system")
REQUIRE = os.environ.get("SYSTEMD_HARDEN_REQUIRE_SYSTEMD") == "1"

pytestmark = pytest.mark.live


def sh(*argv, check=True):
    return subprocess.run(argv, capture_output=True, text=True, check=check)


@pytest.fixture(scope="module")
def demo():
    if not LIVE:
        if REQUIRE:
            pytest.fail("SYSTEMD_HARDEN_REQUIRE_SYSTEMD=1 but this is not root on a machine running systemd")
        pytest.skip("needs root and systemd as PID 1")
    sh(str(ROOT / "examples/demo/setup.sh"), "up")
    yield
    sh(str(ROOT / "examples/demo/setup.sh"), "down", check=False)


def probe(tmp_path, features, *extra):
    out, js = tmp_path / "h.conf", tmp_path / "r.json"
    code = main(
        [
            "probe",
            UNIT,
            "--check",
            CHECK.format(features=features),
            "--allow-restart",
            "--settle",
            "0.5",
            "-q",
            "-o",
            str(out),
            "--json",
            str(js),
            *extra,
        ]
    )
    return code, out.read_text(), json.loads(js.read_text())


def status(data, line):
    return [d["status"] for d in data["directives"] if line in d["lines"]]


def untouched():
    """The unit is running, and nothing of the probe is left on the machine."""
    assert sh("systemctl", "is-active", UNIT).stdout.strip() == "active"
    assert not (Path("/run/systemd/system") / f"{UNIT}.d" / DROPIN_NAME).exists()
    assert RealSystem().leftover_dropins() == []
    assert sh("systemctl", "show", UNIT, "-p", "DropInPaths", "--value").stdout.strip() == ""


def test_a_quick_probe_keeps_what_works_and_leaves_the_machine_as_it_was(demo, tmp_path):
    code, text, data = probe(tmp_path, "ping", "--only", "PrivateTmp,UMask,NoNewPrivileges")
    assert code == 0
    assert data["final_ok"] and data["restore_error"] == ""
    assert data["dropin"] == ["NoNewPrivileges=yes", "PrivateTmp=yes", "UMask=0077"]
    assert text.endswith("[Service]\nNoNewPrivileges=yes\nPrivateTmp=yes\nUMask=0077\n")
    assert data["systemd_version"] >= 249
    untouched()


def test_the_directives_a_service_needs_are_found_by_running_it(demo, tmp_path):
    code, text, data = probe(tmp_path, "tmp,home,var")
    assert code == 0 and data["final_ok"], data["final_reason"]
    # reads /home: hidden by yes, still readable read-only
    assert status(data, "ProtectHome=yes") == ["rejected"]
    assert status(data, "ProtectHome=read-only") == ["accepted"]
    # writes /var/lib: read-only everywhere with strict, writable with full
    assert status(data, "ProtectSystem=strict") == ["rejected"]
    assert status(data, "ProtectSystem=full") == ["accepted"]
    assert status(data, "PrivateTmp=yes") == ["accepted"]
    assert status(data, "NoNewPrivileges=yes") == ["accepted"]
    assert "ProtectHome=read-only" in data["dropin"] and "ProtectSystem=full" in data["dropin"]
    assert "ProtectHome=yes" not in data["dropin"]
    # the service listens on TCP, so an empty network namespace breaks the check
    assert status(data, "PrivateNetwork=yes") == ["rejected"]
    # every rejection comes with a reason
    assert all(d["reason"] for d in data["directives"] if d["status"] == "rejected")
    untouched()

    # the file that was written passes `verify`, and a check that needs more than it allows fails
    drop = tmp_path / "h.conf"
    assert (
        main(
            [
                "verify",
                UNIT,
                "--dropin",
                str(drop),
                "--check",
                CHECK.format(features="tmp,home,var"),
                "--allow-restart",
                "--settle",
                "0.5",
            ]
        )
        == 0
    )
    untouched()
    assert (
        main(
            [
                "verify",
                UNIT,
                "--dropin",
                str(drop),
                "--check",
                CHECK.format(features="etc"),
                "--allow-restart",
                "--settle",
                "0.5",
            ]
        )
        == 1
    )
    untouched()


def test_capabilities_and_system_calls_the_check_exercises_keep_their_directives_out(demo, tmp_path):
    code, _, data = probe(tmp_path, "exec-memory,netlink,namespace,sysctl")
    assert code == 0 and data["final_ok"], data["final_reason"]
    assert status(data, "MemoryDenyWriteExecute=yes") == ["rejected"]
    assert status(data, "RestrictNamespaces=yes") == ["rejected"]
    assert status(data, "ProtectKernelTunables=yes") == ["rejected"]
    assert status(data, "RestrictAddressFamilies=AF_UNIX") == ["rejected"]
    assert status(data, "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6") == ["rejected"]
    for line in ("MemoryDenyWriteExecute=yes", "RestrictNamespaces=yes", "ProtectKernelTunables=yes"):
        assert line not in data["dropin"]
    untouched()


def test_the_exposure_level_drops_when_directives_are_added(demo, tmp_path):
    _, _, data = probe(tmp_path, "tmp,home,var")
    if data["exposure_before"] is None:
        pytest.skip("systemd-analyze security is not available here")
    assert data["exposure_after"] < data["exposure_before"]


def test_a_leftover_drop_in_from_a_killed_run_is_removed_by_cleanup(demo, capsys):
    system = RealSystem()
    system.write_dropin(UNIT, "[Service]\nProtectHome=yes\n")
    assert system.leftover_dropins() == [UNIT]
    assert main(["cleanup", "--dry-run"]) == 0
    assert system.leftover_dropins() == [UNIT]
    assert main(["cleanup"]) == 0
    assert system.leftover_dropins() == []
    sh("systemctl", "restart", UNIT)
    untouched()


def test_a_service_that_is_stopped_is_stopped_afterwards(demo, tmp_path):
    sh("systemctl", "stop", UNIT)
    code, _, data = probe(tmp_path, "ping", "--only", "UMask")
    assert code == 0 and data["dropin"] == ["UMask=0077"]
    assert sh("systemctl", "is-active", UNIT, check=False).stdout.strip() == "inactive"
    sh("systemctl", "start", UNIT)
    untouched()


def test_a_check_that_fails_without_any_change_is_a_baseline_failure(demo, tmp_path, capsys):
    code = main(
        ["probe", UNIT, "--check", CHECK.format(features="nope"), "--allow-restart", "--settle", "0.3", "-q"]
    )
    assert code == 4
    assert "does not pass the health check even with no change" in capsys.readouterr().err
    untouched()


def test_a_unit_that_does_not_exist_is_refused(demo, capsys):
    code = main(["probe", "no-such-thing.service", "--check", "true", "--allow-restart"])
    assert code == 3
    assert "is not loaded" in capsys.readouterr().err
