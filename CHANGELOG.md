# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/), versions follow [SemVer](https://semver.org/).

## Unreleased

## 0.2.0 - 2026-11-26

### Added
- Combination step: when the directives that passed alone conflict and some are dropped, the walk is repeated from
  the other end of the table and the larger set is kept (table order wins a tie), so the order no longer decides alone
  which of two conflicting directives survives.
- `catalogue --json`: the directives, the settings tried and their `since` versions as JSON, for other tools.
- `docs/design-notes.md`: why the tool is built the way it is, what was rejected, how it was checked, and the
  questions this design usually draws.
- `ROADMAP.md`: the next small steps, in order.

### Changed
- Releases: a commit that adds a numbered heading to this file releases that version (the Release workflow tests, builds and
  makes the tag itself). Pushing a `vX.Y.Z` tag or running the workflow by hand still works.

## 0.1.0 - 2026-10-18

First release: `probe`, `verify`, `cleanup` and `catalogue`; a catalogue of 28 directives with weaker fallbacks;
tested on real systemd 249 and 255, x86-64 and arm64.
