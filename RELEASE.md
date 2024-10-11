# Release

A release of scan-action comprises:
- a new semver git tag from the current tip of the main branch
- a new [github release](https://github.com/anchore/scan-action/releases) with a changelog
- the action distributable committed into the repo at `dist/`

Ideally releasing should be done often with small increments when possible. Unless a
breaking change is blocking the release, or no fixes/features have been merged, a good
target release cadence is between every 1 or 2 weeks.


## Creating a release

Releases are automatically drafted on every push to the main branch. Please see the [github releases page](https://github.com/anchore/scan-action/releases) for the latest draft. To publish the release:

- Click "edit" (the pencil icon)
- Modify the changelog as needed (for instance, if grype was bumped multiple times, include only the latest version bump entry)
- Click "publish"
