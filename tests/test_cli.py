import json
import re

import pytest

from systemd_harden.cli import main

from .fake import Break, FakeSystem

CHECK = "curl -fsS http://127.0.0.1:8080/health"


def cli(args, fake=None, capsys=None):
    fake = fake or FakeSystem()
    code = main(args, system=fake)
    cap = capsys.readouterr()
    return code, cap.out, cap.err, fake


def test_probe_writes_the_drop_in_to_stdout_and_the_summary_to_stderr(capsys):
    fake = FakeSystem(breaks={"ProtectHome=yes": Break("check", "No such file or directory")})
    code, out, err, _ = cli(
        ["probe", "demo.service", "--check", CHECK, "--allow-restart", "-q"], fake, capsys
    )
    assert code == 0
    assert out.startswith("# Written by systemd-harden")
    assert "[Service]\nNoNewPrivileges=yes\n" in out
    assert "ProtectHome=read-only" in out
    assert "# Tried and not used:" in out
    assert "ProtectHome=yes: the health check failed" in out
    assert "demo.service on systemd 255" in err
    assert "rejected  ProtectHome" in err and "ProtectHome=yes: the health check failed" in err
    assert "accepted  ProtectHome" in err and "ProtectHome=read-only" in err
    assert "directives kept." in err
    assert "Exposure level by systemd-analyze security" in err
    assert "The service was restarted" in err


def test_probe_reports_rejected_directives_with_a_likely_cause(capsys):
    fake = FakeSystem(breaks={"MemoryDenyWriteExecute=yes": Break("crash", "status=31/SYS")})
    code, out, err, _ = cli(
        ["probe", "demo.service", "--check", CHECK, "--allow-restart", "-q"], fake, capsys
    )
    assert code == 0
    assert re.search(
        r"rejected  MemoryDenyWriteExecute +MemoryDenyWriteExecute=yes: the service is failed/failed", err
    )
    assert "likely: a system call was refused by SystemCallFilter" in err
    assert "MemoryDenyWriteExecute" in out.split("# Tried and not used:")[1].split("[Service]")[0]


def test_probe_progress_lines_go_to_stderr_unless_quiet(capsys):
    _, _, err, _ = cli(
        ["probe", "demo.service", "--check", CHECK, "--allow-restart", "--only", "UMask"], capsys=capsys
    )
    assert "trying UMask" in err
    _, _, err, _ = cli(
        ["probe", "demo.service", "--check", CHECK, "--allow-restart", "--only", "UMask", "-q"], capsys=capsys
    )
    assert "trying UMask" not in err


def test_probe_output_and_json_files(tmp_path, capsys):
    out_file, json_file = tmp_path / "hardening.conf", tmp_path / "r.json"
    code, out, _, _ = cli(
        [
            "probe",
            "demo.service",
            "--check",
            CHECK,
            "--allow-restart",
            "-q",
            "-o",
            str(out_file),
            "--json",
            str(json_file),
            "--only",
            "PrivateTmp,UMask",
        ],
        capsys=capsys,
    )
    assert code == 0 and out == ""
    assert out_file.read_text().endswith("[Service]\nPrivateTmp=yes\nUMask=0077\n")
    data = json.loads(json_file.read_text())
    assert data["unit"] == "demo.service"
    assert data["dropin"] == ["PrivateTmp=yes", "UMask=0077"]
    assert [d["directive"] for d in data["directives"]] == ["PrivateTmp", "UMask"]
    assert data["final_ok"] is True


def test_a_service_that_is_unhealthy_to_begin_with_exits_4(capsys):
    fake = FakeSystem(baseline=Break("check", "Connection refused"))
    code, out, err, _ = cli(
        ["probe", "demo.service", "--check", CHECK, "--allow-restart", "-q"], fake, capsys
    )
    assert code == 4 and out == ""
    assert "does not pass the health check even with no change at all" in err
    assert "likely: the service's network access changed" in err


def test_an_unstable_final_set_exits_1(capsys):
    fake = FakeSystem(flaky_final=True)
    code, _, err, _ = cli(
        ["probe", "demo.service", "--check", CHECK, "--allow-restart", "-q", "--rounds", "4"], fake, capsys
    )
    assert code == 1
    assert "WARNING: the final set did not hold up" in err


def test_a_failed_restore_exits_1_and_says_so(capsys):
    code, _, err, _ = cli(
        ["probe", "demo.service", "--check", CHECK, "--allow-restart", "-q", "--only", "UMask"],
        FakeSystem(restore_fails=True),
        capsys,
    )
    assert code == 1
    assert "WARNING: could not put demo.service back as it was" in err


@pytest.mark.parametrize(
    "args, code, message",
    [
        (["probe", "demo.service", "--check", CHECK], 2, "--allow-restart"),
        (["probe", "demo.service", "--check", "", "--allow-restart"], 2, "--check is empty"),
        (["probe", "demo.service", "--check", "curl 'x", "--allow-restart"], 2, "cannot be parsed"),
        (
            ["probe", "demo.service", "--check", CHECK, "--allow-restart", "--only", "Nope"],
            2,
            "unknown directive Nope",
        ),
        (
            ["probe", "demo.service", "--check", CHECK, "--allow-restart", "--skip", "UMask,Nope"],
            2,
            "unknown directive Nope",
        ),
        (["probe", "demo.service", "--check", CHECK, "--allow-restart", "--rounds", "0"], 2, "--rounds"),
        (["probe", "demo.service", "--check", CHECK, "--allow-restart", "--rounds", "21"], 2, "--rounds"),
        (["probe", "demo.service", "--check", CHECK, "--allow-restart", "--settle", "-1"], 2, "--settle"),
        (
            ["probe", "demo.service", "--check", CHECK, "--allow-restart", "--check-timeout", "0"],
            2,
            "--check-timeout",
        ),
        (["probe", "sshd.service", "--check", CHECK, "--allow-restart"], 2, "depends on"),
        (["probe", "demo", "--check", CHECK, "--allow-restart"], 2, "not a service unit name"),
    ],
)
def test_usage_problems_exit_2(args, code, message, capsys):
    got, out, err, fake = cli(args, capsys=capsys)
    assert got == code
    assert message in err
    assert fake.calls == []  # nothing was touched
    assert out == ""


@pytest.mark.parametrize(
    "kwargs, message",
    [
        ({"root": False}, "run it as root"),
        ({"systemd": False}, "systemd is not the running init system"),
        ({"loaded": False}, "is not loaded"),
    ],
)
def test_environment_problems_exit_3(kwargs, message, capsys):
    got, _, err, _ = cli(
        ["probe", "demo.service", "--check", CHECK, "--allow-restart"], FakeSystem(**kwargs), capsys
    )
    assert got == 3
    assert message in err


def test_ctrl_c_exits_130_and_puts_the_service_back(capsys):
    fake = FakeSystem(interrupt_after_restarts=4)
    got, _, err, _ = cli(["probe", "demo.service", "--check", CHECK, "--allow-restart", "-q"], fake, capsys)
    assert got == 130
    assert "interrupted" in err
    assert fake.dropin is None


def test_the_check_is_run_without_a_shell(capsys):
    seen = []

    class Spy(FakeSystem):
        def run_check(self, argv, timeout):
            seen.append(argv)
            return super().run_check(argv, timeout)

    cli(
        [
            "probe",
            "demo.service",
            "--check",
            "sh -c 'exit 0' ; rm -rf /",
            "--allow-restart",
            "-q",
            "--only",
            "UMask",
        ],
        Spy(),
        capsys,
    )
    assert seen[0] == ("sh", "-c", "exit 0", ";", "rm", "-rf", "/")


def test_verify_with_a_good_drop_in(tmp_path, capsys):
    f = tmp_path / "h.conf"
    f.write_text("# a comment\n[Service]\nPrivateTmp=yes\n\nUMask=0077\n")
    code, out, _, fake = cli(
        ["verify", "demo.service", "--dropin", str(f), "--check", CHECK, "--allow-restart"], capsys=capsys
    )
    assert code == 0
    assert "passes its health check" in out and "2 lines" in out
    assert fake.dropin is None


def test_verify_with_a_breaking_drop_in(tmp_path, capsys):
    f = tmp_path / "h.conf"
    f.write_text("[Service]\nProtectHome=yes\n")
    fake = FakeSystem(breaks={"ProtectHome=yes": Break("check", "No such file or directory")})
    code, _, err, _ = cli(
        ["verify", "demo.service", "--dropin", str(f), "--check", CHECK, "--allow-restart"], fake, capsys
    )
    assert code == 1
    assert "does not pass with" in err and "likely: a path the service needs is no longer visible" in err


@pytest.mark.parametrize(
    "text, message",
    [
        ("[Unit]\nDescription=x\n", "only a [Service] section"),
        ("[Service]\nnot a setting\n", "not a Key=Value line"),
        ("PrivateTmp=yes\n", "only a [Service] section"),
    ],
)
def test_verify_refuses_drop_ins_that_are_not_a_service_section(tmp_path, capsys, text, message):
    f = tmp_path / "h.conf"
    f.write_text(text)
    code, _, err, fake = cli(
        ["verify", "demo.service", "--dropin", str(f), "--check", CHECK, "--allow-restart"], capsys=capsys
    )
    assert code == 2 and message in err and fake.calls == []


def test_verify_with_a_missing_file(tmp_path, capsys):
    code, _, err, _ = cli(
        ["verify", "demo.service", "--dropin", str(tmp_path / "none"), "--check", CHECK, "--allow-restart"],
        capsys=capsys,
    )
    assert code == 2 and "none" in err


def test_cleanup(capsys):
    fake = FakeSystem()
    fake.leftovers = ["a.service", "b.service"]
    code, out, _, _ = cli(["cleanup", "--dry-run"], fake, capsys)
    assert code == 0 and "would remove the probe drop-in of a.service" in out
    assert fake.calls == []
    code, out, _, _ = cli(["cleanup"], fake, capsys)
    assert code == 0 and out.count("removed the probe drop-in") == 2
    assert fake.calls == ["remove", "remove", "reload"]
    fake.leftovers = []
    code, out, _, _ = cli(["cleanup"], fake, capsys)
    assert "no leftover probe drop-ins" in out
    code, _, err, _ = cli(["cleanup"], FakeSystem(root=False), capsys)
    assert code == 3


def test_catalogue_lists_every_directive(capsys):
    code, out, _, _ = cli(["catalogue"], capsys=capsys)
    assert code == 0
    assert "ProtectSystem=strict   (systemd 214+)" in out
    assert out.count("\n") > 60


def test_version(capsys):
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0
    assert capsys.readouterr().out.startswith("systemd-harden 0.1.0")
