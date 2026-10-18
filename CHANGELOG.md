# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/), versions follow [SemVer](https://semver.org/).

## Unreleased

### Added
- `docs/design-notes.md`: why the tool is built the way it is, what was rejected, how it was checked, and the
  questions this design usually draws.
- `ROADMAP.md`: the next small steps, in order.

### Changed
- Releases: a commit that adds a numbered heading to this file releases that version (the Release workflow tests, builds and
  makes the tag itself). Pushing a `vX.Y.Z` tag or running the workflow by hand still works.

## 0.1.0 - 2026-10-18

First release: `probe`, `verify`, `cleanup` and `catalogue`; a catalogue of 28 directives with weaker fallbacks;
tested on real systemd 249 and 255, x86-64 and arm64.
