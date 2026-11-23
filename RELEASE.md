# Release

A release publishes a `vX.Y.Z` git tag, a [GitHub release](https://github.com/anchore/scan-action/releases) with a chronicle-generated changelog, and the committed `dist/index.js`. Aim for a 1–2 week cadence.

From a clean checkout of `main`:

```sh
make release
```

## Updating Grype

`make update-grype-release` repins `GrypeVersion.js` and rebuilds `dist/` — review the diff and open a PR. Requires `gh` auth.
