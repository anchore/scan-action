# GitHub Action for Vulnerability Scanning

[![Test Status][test-img]][test]
[![GitHub release](https://img.shields.io/github/release/anchore/scan-action.svg)](https://github.com/anchore/scan-action/releases/latest)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/anchore/scan-action/blob/main/LICENSE)
[![Slack Invite](https://img.shields.io/badge/Slack-Join-blue?logo=slack)](https://anchore.com/slack)

:zap: _Find threats in files or containers at lightning speed_ :zap:

This is a GitHub Action for invoking the [Grype](https://github.com/anchore/grype) scanner and returning the vulnerabilities found,
and optionally fail if a vulnerability is found with a configurable severity level.

Use this in your workflows to quickly verify files or containers' content after a build and before pushing, allowing PRs, or deploying updates.

The action invokes the `grype` command-line tool, with these benefits:

- Runs locally, without sending data outbound - no credentials required!
- Speedy scan operations
- Scans both paths and container images
- Easy failure evaluation depending on vulnerability severity

The example workflows have lots of usage examples for scanning both containers and directories.

By default, a scan will produce very detailed output on system packages like an RPM or DEB, but also language-based packages. These are some of the supported packages and libraries:

Supported Linux Distributions:

- Alpine
- BusyBox
- CentOS and RedHat
- Debian and Debian-based distros like Ubuntu

Supported packages and libraries:

- Ruby Bundles
- Python Wheel, Egg, `requirements.txt`
- JavaScript NPM/Yarn
- Java JAR/EAR/WAR, Jenkins plugins JPI/HPI
- Go modules

## Container scanning

The simplest workflow for scanning a `localbuild/testimage` container:

```yaml
- name: Set up Docker Buildx
  uses: docker/setup-buildx-action@v1

- name: build local container
  uses: docker/build-push-action@v2
  with:
    tags: localbuild/testimage:latest
    push: false
    load: true

- name: Scan image
  uses: anchore/scan-action@v3
  with:
    image: "localbuild/testimage:latest"
```

## Directory scanning

To scan a directory, add the following step:

```yaml
- name: Scan current project
  uses: anchore/scan-action@v3
  with:
    path: "."
```

The `path` key allows any valid path for the current project. The root of the path (`"."` in this example) is the repository root.

## Scanning an SBOM file

Use the `sbom` key to scan an SBOM file:

```yaml
- name: Create SBOM
  uses: anchore/sbom-action@v0
  with:
    format: spdx-json
    output-file: "${{ github.event.repository.name }}-sbom.spdx.json"

- name: Scan SBOM
  uses: anchore/scan-action@v3
  with:
    sbom: "${{ github.event.repository.name }}-sbom.spdx.json"
```

## Failing a build on vulnerability severity

By default, if any vulnerability at `medium` or higher is seen, the build fails. To have the build step fail in cases where there are vulnerabilities with a severity level different than the default, set the `severity-cutoff` field to one of `low`, `high`, or `critical`:

With a different severity level:

```yaml
- name: Scan image
  uses: anchore/scan-action@v3
  with:
    image: "localbuild/testimage:latest"
    fail-build: true
    severity-cutoff: critical
```

Optionally, change the `fail-build` field to `false` to avoid failing the build regardless of severity:

```yaml
- name: Scan image
  uses: anchore/scan-action@v3
  with:
    image: "localbuild/testimage:latest"
    fail-build: false
```

### Action Inputs

The inputs `image`, `path`, and `sbom` are mutually exclusive to specify the source to scan; all the other keys are optional. These are all the available keys to configure this action, along with the defaults:

| Input Name          | Description                                                                                                                                                                                                                                                      | Default Value |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------- |
| `image`             | The image to scan                                                                                                                                                                                                                                                | N/A           |
| `path`              | The file path to scan                                                                                                                                                                                                                                            | N/A           |
| `sbom`              | The SBOM to scan                                                                                                                                                                                                                                                 | N/A           |
| `registry-username` | The registry username to use when authenticating to an external registry                                                                                                                                                                                         |               |
| `registry-password` | The registry password to use when authenticating to an external registry                                                                                                                                                                                         |               |
| `fail-build`        | Fail the build if a vulnerability is found with a higher severity. That severity defaults to `medium` and can be set with `severity-cutoff`.                                                                                                                     | `true`        |
| `output-format`     | Set the output parameter after successful action execution. Valid choices are `json`, `sarif`, and `table`, where `table` output will print to the console instead of generating a file.                                                                         | `sarif`       |
| `severity-cutoff`   | Optionally specify the minimum vulnerability severity to trigger a failure. Valid choices are "negligible", "low", "medium", "high" and "critical". Any vulnerability with a severity less than this value will lead to a "warning" result. Default is "medium". | `medium`      |
| `only-fixed`        | Specify whether to only report vulnerabilities that have a fix available.                                                                                                                                                                                        | `false`       |

### Action Outputs

| Output Name | Description                                                  | Type   |
| ----------- | ------------------------------------------------------------ | ------ |
| `sarif`     | Path to the SARIF report file, if `output-format` is `sarif` | string |
| `json`      | Path to the report file , if `output-format` is `json`       | string |

### Example Workflows

Assuming your repository has a Dockerfile in the root directory:

```yaml
name: Container Image CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Build the container image
        run: docker build . --file Dockerfile --tag localbuild/testimage:latest
      - uses: anchore/scan-action@v3
        with:
          image: "localbuild/testimage:latest"
          fail-build: true
```

Same example as above, but with SARIF output format - as is the default, the action will generate a SARIF report, which can be uploaded and then displayed as a Code Scanning Report in the GitHub UI.

> :bulb: Code Scanning is a Github service that is currently in Beta. [Follow the instructions on how to enable this service for your project](https://docs.github.com/en/free-pro-team@latest/github/finding-security-vulnerabilities-and-errors-in-your-code/enabling-code-scanning-for-a-repository).

```yaml
name: Container Image CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Build the Container image
        run: docker build . --file Dockerfile --tag localbuild/testimage:latest
      - uses: anchore/scan-action@v3
        id: scan
        with:
          image: "localbuild/testimage:latest"
      - name: upload Anchore scan SARIF report
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: ${{ steps.scan.outputs.sarif }}
```

Optionally, you can add a step to inspect the SARIF report produced:

```yaml
- name: Inspect action SARIF report
  run: cat ${{ steps.scan.outputs.sarif }}
```

## Additional configuration

You may add a `.grype.yaml` file at your repository root
for more [Grype configuration](https://github.com/anchore/grype#configuration)
such as [ignoring certain matches](https://github.com/anchore/grype#specifying-matches-to-ignore).

## anchore/scan-action/download-grype

A sub-action to [download Grype](download-grype/action.yml).

Input parameters:

| Parameter       | Description                                                                                                  | Default |
| --------------- | ------------------------------------------------------------------------------------------------------------ | ------- |
| `grype-version` | An optional Grype version to download, defaults to the pinned version in [GrypeVersion.js](GrypeVersion.js). |         |

Output parameters:

| Parameter | Description                                                          |
| --------- | -------------------------------------------------------------------- |
| `cmd`     | a reference to the [Grype](https://github.com/anchore/grype) binary. |

`cmd` can be referenced in a workflow like other output parameters:
`${{ steps.<step-id>.outputs.cmd }}`

Example usage:

```yaml
- uses: anchore/scan-action/download-grype@v3
  id: grype
- run: ${{steps.grype.outputs.cmd}} dir:.
```

## Contributing

We love contributions, feedback, and bug reports. For issues with the invocation of this action, file [issues](https://github.com/anchore/scan-action/issues) in this repository.

For contributing, see [Contributing](CONTRIBUTING.md).

## More Information

For documentation on Grype itself, including other output capabilities, see the [grype project](https://github.com/anchore/grype)

Connect with the community directly on [slack](https://anchore.com/slack).

[test]: https://github.com/anchore/scan-action
[test-img]: https://github.com/anchore/scan-action/workflows/Tests/badge.svg

## Diagnostics

This action makes extensive use of GitHub Action debug logging,
which can be enabled as [described here](https://github.com/actions/toolkit/blob/master/docs/action-debugging.md)
by setting a secret in your repository of `ACTIONS_STEP_DEBUG` to `true`.
