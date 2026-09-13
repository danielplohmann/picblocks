# Releasing picblocks

This repository follows the release process shared across the MCRIT ecosystem
([smda](https://github.com/danielplohmann/smda), [purepdb](https://github.com/danielplohmann/purepdb),
[mcrit](https://github.com/danielplohmann/mcrit), [mcritweb](https://github.com/fkie-cad/mcritweb),
[mcrit-plugin](https://github.com/danielplohmann/mcrit-plugin),
[docker-mcrit](https://github.com/danielplohmann/docker-mcrit)). The shape is the same everywhere;
this file states the values that are specific to this repository.

## Versioning

picblocks follows [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html) over the block report
format, the database format and the scores the matcher reports; see the note at the top of
`CHANGELOG.md`.

The version is declared in `pyproject.toml` (`[project].version`); the package reads it back through
`importlib.metadata` and declares no second copy. The release workflow refuses a tag that does not
match it, so a bump that misses it fails before anything is published.

## Changelog

`CHANGELOG.md` follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). It is the one
authoritative record of what a release contains: the GitHub release notes are generated from it, and
nothing is written twice.

- Every pull request that changes something a user can observe adds its own bullet under
  `## [Unreleased]`, in the subsection it belongs to (`Added`, `Changed`, `Deprecated`, `Removed`,
  `Fixed`, `Security`), while the change is fresh. The `Changelog` check fails a PR that touches
  `picblocks/` or `pyproject.toml` without touching `CHANGELOG.md`; apply the `no-changelog` label
  when a change genuinely needs no entry (a typo, a CI-only change), and say why in the PR.
- An entry says what changed and what it costs the reader: whether older block reports, databases
  or scores stay comparable, which issue or PR it closes.
- Dependency bumps need no entry. GitHub lists them under their own heading in the release notes,
  from the `dependencies` / `github_actions` labels (`.github/release.yml`).

## Cutting a release

1. Check that `master` is green and that everything meant for the release has merged.
2. In one commit on a branch, then merged through a PR:
   - set the new version in `pyproject.toml`;
   - in `CHANGELOG.md`, rename `## [Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD`, drop the empty
     subsections, open a fresh empty `## [Unreleased]` above it, and update the compare links at
     the foot of the file.
3. Wait for CI to pass on the merge commit. Then tag that commit and push the tag:

   ```bash
   git tag -a vX.Y.Z -m "picblocks X.Y.Z"
   git push origin vX.Y.Z
   ```

Pushing the tag is the release. `.github/workflows/publish-release.yml` then:

1. **Verify** — refuses to continue unless the tag matches `pyproject.toml`, `CHANGELOG.md` has a
   `## [X.Y.Z] - <date>` section (which becomes the release notes), the tagged commit is on
   `master`, and the `Tests` workflow passed on that commit.
2. **Build** — builds the sdist and wheel in an isolated environment, checks their metadata with
   `twine check --strict`, and installs the wheel into a clean virtual environment carrying only
   the declared runtime dependencies to import the hasher and the matcher from it.
3. **Publish** — uploads to PyPI through [trusted publishing](https://docs.pypi.org/trusted-publishers/)
   with signed provenance attestations. No API token is stored anywhere.
4. **Release** — creates the GitHub release for the tag with the changelog section as its body,
   GitHub's generated contributor and PR list appended under it, and the sdist and wheel attached.

Each gate fails with a message naming what to fix. Nothing has to be remembered at the console.

## Pre-releases

A release candidate is tagged `vX.Y.Zrc1` (also `a1`, `b1`), with the same version string in
`pyproject.toml` and a `## [X.Y.Zrc1] - YYYY-MM-DD` changelog section. The workflow marks the
GitHub release as a pre-release and does not make it "latest". PyPI does not install a pre-release
unless it is asked for explicitly (`pip install --pre`).

## Rehearsing

Run *Publish release* manually from the Actions tab, choosing a tag as the ref. A manual run goes
through the same gates and build, publishes to [TestPyPI](https://test.pypi.org/p/picblocks) instead
of PyPI (an already-present version is skipped rather than failed), and stops before creating the
GitHub release. Rehearse the first release after any change to the workflow.

## When a release fails

- **A gate failed before anything was published** (tag/version mismatch, missing changelog section,
  tag not on `master`, CI not green): fix the cause on `master`, delete the tag locally and on the
  remote (`git push --delete origin vX.Y.Z`), and tag again once the fix has merged. Nothing needs
  cleaning up.
- **Publishing to PyPI failed part-way**: a version number on PyPI is permanent even when yanked,
  so do not try to reuse it. Fix the cause, bump the patch version, and release again. Yank the
  incomplete version on PyPI if any of its files were accepted.
- **The GitHub release step failed after publishing**: re-run only the failed job from the Actions
  UI; the built artifacts are kept as workflow artifacts and the step is idempotent.

## Maintainer configuration

Done once, by a repository owner; the workflow cannot create these for itself.

- **PyPI trusted publisher** for the `picblocks` project: owner `danielplohmann`, repository
  `picblocks`, workflow `publish-release.yml`, environment `pypi`. Add the same publisher on
  TestPyPI with environment `testpypi` to enable rehearsals.
- **GitHub environments** `pypi` and `testpypi` (Settings → Environments). Restricting `pypi` to
  the `v*` tag pattern and requiring a reviewer is recommended.
- **Label** `no-changelog`, used by the changelog check.
- Optionally, **immutable releases** (Settings → General → Releases).

## Release order across the ecosystem

picblocks depends on `smda` (`>=4.2.13`) and is depended on by `mcrit` (`>=1.1.2`). When a change
here needs a newer smda, release smda first and raise the floor in `pyproject.toml`; when a change
here is needed by MCRIT, release picblocks first, then MCRIT with its floor raised.
