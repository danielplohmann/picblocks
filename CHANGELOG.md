# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) over the block report format,
the database format and the scores the matcher reports: a release after which reports or scores
from an older version are no longer comparable says so, as v2.0.0 and v2.1.0 did.

Add your entry to `[Unreleased]` when the change merges, while the reasoning is still at hand,
rather than reconstructing it from the commit log at release time.

## [Unreleased]

### Added

- Pushing a `vX.Y.Z` tag now publishes the release. The workflow refuses to continue unless the tag
  matches `pyproject.toml`, `CHANGELOG.md` has a section for it, the commit is on `master` and CI
  passed there; it then builds the sdist and wheel in an isolated environment, installs the wheel
  into a clean environment to import it, uploads to PyPI through trusted publishing with signed
  provenance, and creates the GitHub release from that version's changelog section with the
  generated contributor list appended. Pre-release tags (`v2.2.0rc1`) are marked as such, and a
  manual run rehearses the same path against TestPyPI. Before, publishing was `make publish`
  with an API token and there were no GitHub releases. See `RELEASING.md`; the trusted publisher
  and the `pypi` and `testpypi` environments are configured once by a maintainer.
- A pull request that changes `picblocks/` or `pyproject.toml` has to add a `CHANGELOG.md` entry or
  carry the `no-changelog` label; CI checks it.

### Changed

- The release history moved out of `README.md` into this file; the entries below are unchanged.
- `requirements.txt` and `pytest.ini` folded into `pyproject.toml`, which was already the single
  source of the dependencies; `make init` installs `.[web,dev]`.

### Removed

- **Python 3.11 is no longer supported**; `requires-python` is `>=3.12`. Nothing in picblocks
  needed 3.12 - the MCRIT ecosystem now shares a 3.12 floor so one interpreter serves every
  component.

## Older releases

Recorded as they were written in the README at the time, newest first.

* 2026-09-13: v2.1.0 - architecture-aware PIC escaping (SMDA >= 4.2.13, AArch64/CIL/Dalvik as well as Intel), corrected matcher scoring (see above), dump/baseaddress routing, report/UI fixes, and a test suite
* 2023-11-24: v2.0.1 - SMDA pinned to 1.12.7 before our bigger fix for PIC calculation
* 2022-09-08: v2.0.0 - (BREAKING CHANGE) now intraprocedural control flow transfers are wildcarded by default, which should improve matching
* 2022-08-04: v1.1.3 - extended format for blockhash representation of functions
* 2021-10-01: v1.1.1 - added script to check detection rates and relative web interface page
* 2021-09-28: v1.1.0 - added simple web user interface and a db connection
* 2021-09-12: v1.0.6 - added submission form fields for bitness and base address to force overrides for those values.
* 2021-08-24: v1.0.5 - improved parsing of bitness from submission filenames.
* 2021-08-20: v1.0.4 - Tweaked result visualization, now showing all unique matches beyond the first 20.

[Unreleased]: https://github.com/danielplohmann/picblocks/compare/v2.1.0...HEAD
