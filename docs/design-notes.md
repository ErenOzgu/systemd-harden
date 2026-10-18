# Design notes

Why systemd-harden is built the way it is. The README says what it does; this says what was decided and what else was
considered.

## The problem in one paragraph

systemd can take a lot away from a service: write access to the system, other users' processes, kernel tunables,
system calls, network families. Which of those a given service survives is not written anywhere. It is found by
adding a directive, restarting, and waiting to see what breaks, sometimes an hour later. So most services stay
unhardened, or get a block of directives copied from a program that behaved differently. The aim is to turn the
guessing into an experiment that can be repeated.

## Decisions

### An experiment, not an analysis

The alternatives are to read the binary, to trace system calls and build an allow list from one run, or to trust a
score. Each of those infers what the service needs. Here the service is simply run under the restriction and the
question "does it still work?" is answered by running it. That is slower (about thirty-five restarts) but it cannot
disagree with reality about the directives it tests. The price is that it only knows what the health check exercises,
and the README says so first among its limits.

`systemd-analyze security` is used, but only as information: its score is shown before and after, never used to decide.

### The health check is yours

The tool cannot know what "working" means for a service. A check that only asks "is the port open?" would pass a
directive that breaks the one request that writes to disk. So the check is a command the user supplies, run without a
shell, and the README spends a section on writing a good one. A baseline run with no change must pass first; if it does
not, nothing that follows would mean anything and the probe stops with its own exit status (4).

### One directive at a time, strongest first, then weaker variants

Each directive has a short list of candidates ordered from strongest to weakest (`ProtectHome=yes`, then
`read-only`). The first one that holds is kept. This gives the strongest setting per directive without searching the
whole space, and the order is written down in a table that the README is generated from.

### A service must stay up, not just start

After each restart the service must still be running after `--settle` seconds, and only then is the check run. Some
failures are not at start: a process that dies after loading a plugin looks like a pass if the check is run at once.

### The combination is greedy, and says so

Directives that pass alone can still conflict. The tool first tries them all together; if that fails it adds them one
by one in table order and drops the ones that break the set, with the reason. A different order could keep a larger
set. Finding the best subset would mean many more restarts, so the cheap, deterministic rule was chosen and the
limitation stated.

### A directive that is silently ignored must not look like a pass

An older systemd ignores a line it does not know, with a warning. That would be counted as "the service survived".
So every candidate has a `since` version and is skipped on older systemd, and for single-word settings the tool reads
the value back with `systemctl show` to confirm it is really in effect (another drop-in could override it). List-valued
settings (`SystemCallFilter`, `RestrictAddressFamilies`, `CapabilityBoundingSet`, `IPAddressDeny`) are not read back;
this is a stated limit and a roadmap item.

### The probe changes nothing permanent

The probe's drop-in is written under `/run/systemd/system`, which disappears on reboot, and removed at the end; the
service is returned to the state it was in (running or stopped). The result is printed, and the user installs it under
`/etc` themselves. If the probe is killed the drop-in stays until `systemd-harden cleanup` (or a reboot), which is a
stated limit.

### It refuses what it should not touch

It needs root and a running systemd (exit 3), `--allow-restart` must be given (it restarts the service many times),
and units such as sshd, dbus and systemd's own need `--allow-critical`.

### `verify` keeps the result honest

A drop-in rots when the service changes. `verify` applies an existing drop-in once more and runs the check, so a pull
request that starts using a path the drop-in made read-only fails in CI, not in production.

## How it was checked

* The whole algorithm runs against a simulated machine whose behaviour depends on the drop-in it is given: weaker
  candidates, conflicts, a service that dies after the settle time, an old systemd, a failed restore, a flaky final
  set, an interrupt in the middle, every refusal.
* Parsers are tested against stand-in executables for `systemctl`, `journalctl` and `systemd-analyze`.
* **Real systemd in CI**, Ubuntu 22.04 (systemd 249) and 24.04 (255) on x86-64 and 24.04 on arm64: a demo service is
  probed and verified for real, and the tests assert what systemd does (`ProtectHome=yes` breaks a service that reads
  `/home` while `read-only` does not, and so on). A skipped live test is a failure in CI.
* **A mutation check, once and by hand.** 67 small changes to the source (a condition turned off, a comparison loosened,
  a constant changed) were made one at a time in a copy, and the tests that need no real systemd were run. Twelve
  survived the first pass; tests were added for them and all 67 are caught now. The script is not in the repository and
  the check is not in CI.

## What would be changed next

See [ROADMAP.md](../ROADMAP.md). In order: newer directives (`PrivateIPC`, `ProtectHome=tmpfs`), reading back list
values, a second search order for the combination step, and trying a systemd newer than 255.

## Questions this design usually draws

**Why not trace system calls and build the filter from that?** That infers from one run what the service needs. This
tests the real restriction on the real service, and does not guess. It does not tune an allow list either (stated).

**Is it safe to run?** It restarts the service about thirty-five times, so not on something that must stay up. It
refuses critical units without a flag and puts the service back as it found it.

**How do you know a directive was really applied?** Single-word settings are read back with `systemctl show`; a
directive newer than the running systemd is skipped, not counted as a pass.

**What is not covered?** Whatever the health check does not exercise; list-valued settings are not read back; user
services, sockets and timers are not handled; only Ubuntu 22.04 and 24.04 were tried.

**Why is the combination greedy?** The best subset would cost far more restarts. Table order is deterministic and the
README states the limit.

## Three-minute demo

```sh
pip install git+https://github.com/ErenOzgu/systemd-harden
git clone https://github.com/ErenOzgu/systemd-harden && cd systemd-harden
sudo examples/demo/setup.sh up
sudo systemd-harden probe sdh-demo.service --allow-restart \
     --check "python3 /usr/local/lib/systemd-harden-demo/service.py check tmp,home,var" -o hardening.conf
sudo examples/demo/setup.sh down
```

What to say: the demo service reads `/home`, writes under `/var/lib` and uses `/tmp`. The table on standard error shows
`ProtectHome=yes` rejected and `read-only` accepted, `ProtectSystem=strict` rejected and `full` accepted, and the
exposure level falling from 9.6 to 1.4. Use a throw-away VM; it restarts the service many times.
