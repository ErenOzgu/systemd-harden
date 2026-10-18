# Roadmap

Small steps, in order. A step is done when it has tests, the README says what changed, CI is green and the CHANGELOG
has a line for it. Each step is meant to be a few hours of work, not a rewrite.

- [ ] `PrivateIPC=yes` (systemd 248) in the catalogue. The committed real-run output in `examples/demo/real-run/` has
      to be regenerated from a CI run in the same change, so that it still matches what the tool does
- [ ] `ProtectHome=tmpfs` (systemd 238) as the middle candidate between `yes` and `read-only`, with the unit tests that
      assume the order updated
- [ ] Read list-valued directives back, starting with `RestrictAddressFamilies`: compare `systemctl show` with the
      drop-in on systemd 249 and 255, and say "not verified" where the output format differs
- [ ] A second search order for the combination step: try table order and reverse order and keep the larger set
- [ ] `catalogue --json`, for tools that want the table and the `since` versions
- [ ] A live check on a newer systemd than 255 (the README says only 249 and 255 were tried)
