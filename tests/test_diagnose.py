import random

import pytest

from systemd_harden.diagnose import hint, short


@pytest.mark.parametrize(
    "text, fragment",
    [
        ("Main process exited, code=killed, status=31/SYS", "SystemCallFilter"),
        ("demo.service: Failed with result 'signal'. Bad system call", "SystemCallFilter"),
        ("Main process exited, code=exited, status=226/NAMESPACE", "namespace"),
        ("Failed to set up mount namespacing: /home: No such file or directory", "namespace"),
        ("status=218/CAPABILITIES", "capability"),
        ("status=228/SECCOMP", "seccomp"),
        ("status=217/USER", "service user"),
        ("status=203/EXEC", "could not be executed"),
        ("OSError: [Errno 30] Read-only file system: '/var/lib/x'", "read-only"),
        ("socket.error: [Errno 97] Address family not supported by protocol", "socket family"),
        ("connect: Network is unreachable", "network access"),
        ("PermissionError: [Errno 1] Operation not permitted", "forbids"),
        ("open(/etc/x): Permission denied", "refused access"),
        ("FileNotFoundError: [Errno 2] No such file or directory: '/home/app'", "no longer visible"),
    ],
)
def test_known_failures_get_a_plain_sentence(text, fragment):
    assert fragment in hint(text)


def test_the_most_specific_cause_wins():
    assert "SystemCallFilter" in hint("No such file or directory", "status=31/SYS")


def test_unknown_text_gets_no_hint():
    assert hint("", "all fine") == ""
    assert hint() == ""


def test_short_keeps_the_last_three_lines_on_one_line():
    assert short("a\n\n  b  c \nd\ne\n") == "b c | d | e"
    assert short("") == ""
    assert short("x" * 1000, 50).startswith("…") and len(short("x" * 1000, 50)) == 50


def test_short_and_hint_survive_random_text():
    rng = random.Random(7)
    alphabet = "abc \n\té\x00\x1b[31m=/-_SYS31"
    for _ in range(500):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 400)))
        assert len(short(text, 80)) <= 80
        hint(text)
