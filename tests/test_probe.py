import pytest

from systemd_harden.catalogue import CATALOGUE
from systemd_harden.probe import (
    ACCEPTED,
    DROPPED,
    REJECTED,
    SKIPPED,
    BaselineFailed,
    Refusal,
    Settings,
    probe,
    verify,
)

from .fake import Break, FakeSystem

UNIT = "demo.service"
CHECK = ("curl", "-fsS", "http://127.0.0.1:8080/health")


def settings(**kw):
    kw.setdefault("check", CHECK)
    kw.setdefault("settle", 1.0)
    return Settings(**kw)


def run(fake, **kw):
    return probe(fake, UNIT, settings(**kw), allow_restart=True)


def trial(result, key):
    """The last candidate tried for the directive: the accepted one, or the weakest one that failed."""
    return [t for t in result.trials if t.key == key][-1]


def tried(result, key):
    return [(t.lines, t.status) for t in result.trials if t.key == key]


def test_a_service_that_survives_everything_gets_the_strongest_setting_of_every_directive():
    fake = FakeSystem()
    result = run(fake)
    assert result.final_ok
    assert [t.key for t in result.final] == [d.key for d in CATALOGUE]
    assert all(t.status == ACCEPTED for t in result.trials)
    assert result.lines()[0] == "NoNewPrivileges=yes"
    assert "ProtectSystem=strict" in result.lines()
    assert "SystemCallFilter=~@privileged @resources" in result.lines()
    # one restart for the baseline, one per directive, one together, two final rounds, one to restore
    assert result.restarts == 1 + len(CATALOGUE) + 1 + 2
    assert fake.restarts == result.restarts + 1


def test_the_baseline_runs_with_no_drop_in_and_the_probe_drop_in_is_gone_at_the_end():
    fake = FakeSystem()
    run(fake)
    assert fake.dropin is None
    assert fake.loaded_dropin is None
    assert fake.calls[:3] == ["remove", "remove", "reload"]


def test_a_weaker_candidate_is_used_when_the_strongest_breaks_the_service():
    fake = FakeSystem(
        breaks={"ProtectHome=yes": Break("check", "cannot read /home/app/data: No such file or directory")}
    )
    result = run(fake)
    t = trial(result, "ProtectHome")
    assert t.status == ACCEPTED
    assert t.lines == ("ProtectHome=read-only",)
    assert tried(result, "ProtectHome") == [
        (("ProtectHome=yes",), REJECTED),
        (("ProtectHome=read-only",), ACCEPTED),
    ]
    assert "ProtectHome=read-only" in result.lines()
    assert "ProtectHome=yes" not in result.lines()


def test_a_directive_whose_every_candidate_breaks_the_service_is_rejected_with_the_reason_and_a_hint():
    fake = FakeSystem(
        breaks={
            "MemoryDenyWriteExecute=yes": Break("crash", "Main process exited, code=killed, status=31/SYS"),
        }
    )
    result = run(fake)
    t = trial(result, "MemoryDenyWriteExecute")
    assert t.status == REJECTED
    assert "failed/failed" in t.reason and "exit status 31" in t.reason
    assert "SystemCallFilter" in t.hint
    assert "MemoryDenyWriteExecute=yes" not in result.lines()


def test_a_service_that_does_not_start_is_rejected_with_systemds_message():
    fake = FakeSystem(
        breaks={
            "PrivateTmp=yes": Break(
                "start", "Job for demo.service failed because the control process exited with error code."
            )
        }
    )
    result = run(fake)
    t = trial(result, "PrivateTmp")
    assert t.status == REJECTED
    assert t.reason.startswith("the service did not start: Job for demo.service failed")


def test_a_failing_health_check_is_rejected_with_its_output():
    fake = FakeSystem(
        breaks={"NoNewPrivileges=yes": Break("check", "curl: (7) Failed to connect\nConnection refused")}
    )
    result = run(fake)
    t = trial(result, "NoNewPrivileges")
    assert t.status == REJECTED
    assert (
        t.reason
        == "the health check failed (exit status 1): curl: (7) Failed to connect | Connection refused"
    )
    assert "network access changed" in t.hint


def test_a_health_check_that_hangs_is_rejected_as_a_timeout():
    fake = FakeSystem(breaks={"RemoveIPC=yes": Break("hang")})
    result = run(fake, check_timeout=7)
    assert trial(result, "RemoveIPC").reason == "the health check did not finish within 7 s"


def test_a_service_that_systemd_keeps_restarting_is_rejected():
    fake = FakeSystem(breaks={"LockPersonality=yes": Break("loop")})
    result = run(fake)
    t = trial(result, "LockPersonality")
    assert t.status == REJECTED
    assert "3 automatic restarts" in t.reason


def test_directives_an_older_systemd_does_not_know_are_skipped_not_passed():
    fake = FakeSystem(version=241)
    result = run(fake)
    assert trial(result, "ProtectClock").status == SKIPPED
    assert trial(result, "ProtectClock").reason == "needs systemd 245, this is 241"
    assert trial(result, "ProtectProc").status == SKIPPED
    assert trial(result, "RestrictSUIDSGID").status == SKIPPED
    assert trial(result, "NoNewPrivileges").status == ACCEPTED
    assert "ProtectClock=yes" not in result.lines()


def test_a_directive_the_running_systemd_does_not_report_is_skipped():
    fake = FakeSystem(unknown={"ProtectKernelLogs"})
    result = run(fake)
    t = trial(result, "ProtectKernelLogs")
    assert t.status == SKIPPED
    assert "does not know the directive" in t.reason


def test_a_directive_that_another_drop_in_overrides_is_skipped():
    fake = FakeSystem(overridden={"PrivateTmp": "no"})
    result = run(fake)
    t = trial(result, "PrivateTmp")
    assert t.status == SKIPPED
    assert "systemd reports PrivateTmp=no instead of yes" in t.reason


def test_the_first_candidate_that_is_not_in_effect_does_not_stop_the_next_from_being_tried():
    class Picky(FakeSystem):
        def show_value(self, unit, prop):
            if prop == "ProtectSystem" and "ProtectSystem=strict" in self._lines():
                return "full"
            return super().show_value(unit, prop)

    result = run(Picky())
    assert trial(result, "ProtectSystem").lines == ("ProtectSystem=full",)
    assert trial(result, "ProtectSystem").status == ACCEPTED


def test_directives_that_work_alone_but_not_together_are_added_one_by_one_and_the_late_one_is_dropped():
    fake = FakeSystem(conflicts=[("PrivateDevices=yes", "DevicePolicy=closed")])
    result = run(fake)
    assert trial(result, "PrivateDevices").status == ACCEPTED
    assert trial(result, "DevicePolicy").status == DROPPED
    assert "works alone, but not together" in trial(result, "DevicePolicy").reason
    assert "PrivateDevices=yes" in result.lines()
    assert "DevicePolicy=closed" not in result.lines()
    assert result.final_ok


def test_when_the_final_set_is_flaky_the_result_says_so():
    fake = FakeSystem(flaky_final=True)
    result = run(fake, rounds=4)
    assert not result.final_ok
    assert result.final_reason.startswith("final check")


def test_the_exposure_score_is_read_before_and_after():
    result = run(FakeSystem())
    assert result.exposure_before == 9.6
    assert result.exposure_after < result.exposure_before


def test_without_systemd_analyze_the_scores_are_none():
    result = run(FakeSystem(exposure=False))
    assert result.exposure_before is None and result.exposure_after is None


def test_only_and_skip():
    result = run(FakeSystem(), only=("PrivateTmp", "UMask"))
    assert [t.key for t in result.trials] == ["PrivateTmp", "UMask"]
    result = run(FakeSystem(), skip=("PrivateTmp",))
    assert trial(result, "PrivateTmp").status == SKIPPED
    assert trial(result, "PrivateTmp").reason == "left out with --skip"
    assert "PrivateTmp=yes" not in result.lines()


def test_nothing_accepted_means_no_final_stage_and_an_empty_drop_in():
    fake = FakeSystem(
        breaks={line: Break("check", "no") for d in CATALOGUE for c in d.candidates for line in c.lines}
    )
    result = run(fake)
    assert result.lines() == []
    assert result.final_ok
    assert all(t.status == REJECTED for t in result.trials)
    assert result.exposure_after == result.exposure_before


def test_a_service_that_was_stopped_is_stopped_again():
    fake = FakeSystem(active=False)
    run(fake)
    assert fake.stops == 1
    assert fake.calls[-1] == "stop"


def test_a_service_that_was_running_is_running_again_without_the_drop_in():
    fake = FakeSystem()
    run(fake)
    assert fake.calls[-3:] == ["remove", "reload", "restart"]
    assert fake.unit_state(UNIT).active == "active"


def test_a_baseline_that_fails_stops_everything_and_puts_the_service_back():
    fake = FakeSystem(baseline=Break("check", "Connection refused"))
    with pytest.raises(BaselineFailed) as info:
        run(fake)
    assert "health check failed" in info.value.reason
    assert fake.dropin is None
    assert fake.calls.count("write") == 0


def test_an_interrupt_in_the_middle_removes_the_drop_in_and_restarts_the_service():
    fake = FakeSystem(interrupt_after_restarts=5)
    with pytest.raises(KeyboardInterrupt):
        run(fake)
    assert fake.dropin is None
    assert fake.calls[-3:] == ["remove", "reload", "restart"]


def test_a_failed_restore_is_reported_not_hidden():
    fake = FakeSystem(restore_fails=True)
    result = run(fake)
    assert result.restore_error.startswith("could not put demo.service back as it was")


def test_a_failing_daemon_reload_is_an_error():
    fake = FakeSystem(reload_fails=True)
    with pytest.raises(Refusal, match="daemon-reload failed"):
        run(fake)


@pytest.mark.parametrize(
    "kwargs, message",
    [
        ({"root": False}, "run it as root"),
        ({"systemd": False}, "systemd is not the running init system"),
        ({"loaded": False}, "is not loaded"),
    ],
)
def test_the_probe_refuses_on_a_machine_that_cannot_do_it(kwargs, message):
    with pytest.raises(Refusal, match=message):
        run(FakeSystem(**kwargs))


def test_the_probe_refuses_without_allow_restart():
    with pytest.raises(Refusal, match="--allow-restart") as info:
        probe(FakeSystem(), UNIT, settings(), allow_restart=False)
    assert info.value.code == 2


@pytest.mark.parametrize(
    "unit",
    [
        "sshd.service",
        "ssh.service",
        "dbus.service",
        "systemd-logind.service",
        "docker.service",
        "getty@tty1.service",
        "NetworkManager.service",
    ],
)
def test_critical_units_are_refused_unless_forced(unit):
    with pytest.raises(Refusal, match="depends on"):
        probe(FakeSystem(), unit, settings(), allow_restart=True)
    assert probe(
        FakeSystem(), unit, settings(only=("UMask",)), allow_restart=True, allow_critical=True
    ).final_ok


@pytest.mark.parametrize(
    "unit",
    ["demo", "demo.socket", "../x.service", "a b.service", "", "demo.service; id", "x" * 300 + ".service"],
)
def test_unit_names_must_be_service_names(unit):
    with pytest.raises(Refusal, match="not a service unit name") as info:
        probe(FakeSystem(), unit, settings(), allow_restart=True)
    assert info.value.code == 2


def test_a_health_check_is_required():
    with pytest.raises(Refusal, match="health check"):
        probe(FakeSystem(), UNIT, Settings(check=()), allow_restart=True)


def test_oneshot_services_need_not_stay_active():
    class OneShot(FakeSystem):
        def unit_state(self, unit):
            st = super().unit_state(unit)
            return type(st)(load=st.load, active="inactive", sub="dead", result="success")

    with pytest.raises(BaselineFailed):
        run(OneShot())
    result = run(OneShot(), oneshot=True)
    assert result.final_ok


def test_a_service_that_dies_after_the_settle_time_is_caught_by_the_second_look():
    class Dies(FakeSystem):
        def run_check(self, argv, timeout):
            r = super().run_check(argv, timeout)
            if "RestrictRealtime=yes" in self._lines():
                self._outcome = Break("crash", "status=31/SYS")
            return r

    result = run(Dies())
    t = trial(result, "RestrictRealtime")
    assert t.status == REJECTED
    assert t.reason.endswith("while the health check ran")


def test_verify_passes_with_a_working_drop_in_and_puts_the_service_back():
    fake = FakeSystem()
    ok, reason, why, restore = verify(
        fake, UNIT, ["PrivateTmp=yes", "UMask=0077"], settings(), allow_restart=True
    )
    assert ok and reason == "" and restore == ""
    assert fake.dropin is None
    assert fake.restarts == 2 + 1


def test_verify_fails_with_a_breaking_drop_in():
    fake = FakeSystem(breaks={"ProtectHome=yes": Break("check", "No such file or directory")})
    ok, reason, why, _ = verify(
        fake, UNIT, ["PrivateTmp=yes", "ProtectHome=yes"], settings(), allow_restart=True
    )
    assert not ok
    assert "health check failed" in reason
    assert "no longer visible" in why
    assert fake.dropin is None


def test_verify_refuses_like_the_probe():
    with pytest.raises(Refusal):
        verify(FakeSystem(), UNIT, ["UMask=0077"], settings(), allow_restart=False)
    with pytest.raises(Refusal):
        verify(FakeSystem(root=False), UNIT, ["UMask=0077"], settings(), allow_restart=True)


def test_a_start_that_never_finishes_is_reported_as_a_timeout_not_as_a_failed_start():
    fake = FakeSystem(breaks={"PrivateTmp=yes": Break("start-hang")})
    result = run(fake, start_timeout=12)
    assert "did not finish starting within 12 s" in trial(result, "PrivateTmp").reason
    assert trial(result, "PrivateTmp").status == REJECTED


def test_every_experiment_waits_for_the_settle_time():
    fake = FakeSystem()
    start = fake.clock
    result = run(fake, settle=2.5)
    assert fake.clock - start == pytest.approx(2.5 * result.restarts)


def test_a_systemd_version_that_cannot_be_read_is_refused():
    with pytest.raises(Refusal, match="systemd version"):
        run(FakeSystem(version=0))


def test_verify_stops_at_the_first_failing_round():
    fake = FakeSystem(breaks={"ProtectHome=yes": Break("check", "No such file or directory")})
    ok, *_ = verify(fake, UNIT, ["ProtectHome=yes"], settings(rounds=5), allow_restart=True)
    assert not ok
    assert fake.restarts == 1 + 1  # the failing round, and putting the service back


def test_the_final_set_is_applied_again_when_the_last_one_tried_was_the_one_dropped():
    # UMask is the last directive in the table: it is added last, breaks the set and is dropped. The drop-in on
    # disk then still holds the failing set, so the final check must write the surviving set first.
    fake = FakeSystem(conflicts=[("NoNewPrivileges=yes", "UMask=0077")])
    result = run(fake)
    assert trial(result, "UMask").status == DROPPED
    assert result.final_ok
    assert "UMask=0077" not in result.lines()
