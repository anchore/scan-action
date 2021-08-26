[![Test Status][test-img]][test]

# GitHub Action for vulnerability Scanning

:zap: _Find threats in files or containers at lightning speed_ :zap:

This is a GitHub Action for invoking the [grype](https://github.com/anchore/grype) scanner and returning the vulnerabilities found,
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
   uses: anchore/scan-action@v2
   with:
     image: "localbuild/testimage:latest"
```

## Directory scanning

To scan a directory, add the following step:

```yaml
- name: Scan current project
  uses: anchore/scan-action@v2
  with:
    path: "."
```

The `path` key allows any valid path for the current project. The root of the path (`"."` in this example) is the repository root.

## Failing a build on vulnerability severity

By default, if any vulnerability at `medium` or higher is seen, the build fails. To have the build step fail in cases where there are vulnerabilities with a severity level different than the default, set the `severity-cutoff` field to one of `low`, `high`, or `critical`:

With a different severity level:

```yaml
- name: Scan image
  uses: anchore/scan-action@v2
  with:
    image: "localbuild/testimage:latest"
    fail-build: true
    severity-cutoff: critical
```

Optionally, change the `fail-build` field to `false` to avoid failing the build regardless of severity:

```yaml
- name: Scan image
  uses: anchore/scan-action@v2
  with:
    image: "localbuild/testimage:latest"
    fail-build: false
```

### Action Inputs

The only required key is `image` or `path`; all the other keys are optional. These are all the available keys to configure this action, along with its defaults:

| Input Name          | Description                                                                                                                                                                                                                                                                                                    | Default Value |
| ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------- |
| `image`             | The image to scan, this is mutually exclusive to `path`                                                                                                                                                                                                                                                        | N/A           |
| `path`              | The file path to scan, this is mutually exclusive to `image`                                                                                                                                                                                                                                                   | N/A           |
| `debug`             | Verbose logging output                                                                                                                                                                                                                                                                                         | `false`       |
| `fail-build`        | Fail the build if a vulnerability is found with a higher severity. That severity defaults to `"medium"` and can be set with `severity-cutoff`.                                                                                                                                                                 | `true`        |
| `acs-report-enable` | Generate a SARIF report and set the `sarif` output parameter after successful action execution. This report is compatible with GitHub Automated Code Scanning (ACS), as the artifact to upload for display as a Code Scanning Alert report.                                                                    | `true`        |
| `severity-cutoff`   | With ACS reporting enabled, optionally specify the minimum vulnerability severity to trigger an "error" level ACS result. Valid choices are "negligible", "low", "medium", "high" and "critical". Any vulnerability with a severity less than this value will lead to a "warning" result. Default is "medium". | `"medium"`    |

### Action Outputs

| Output Name | Description                   | Type   |
| ----------- | ----------------------------- | ------ |
| sarif       | Path to the SARIF report file | string |

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
      - uses: anchore/scan-action@v2
        with:
          image: "localbuild/testimage:latest"
          fail-build: true
```

Same example as above, but with Automated Code Scanning (ACS) feature enabled - with this example, the action will generate a SARIF report, which can be uploaded and then displayed as a Code Scanning Report in the GitHub UI.

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
      - uses: anchore/scan-action@v2
        id: scan
        with:
          image: "localbuild/testimage:latest"
          acs-report-enable: true
      - name: upload Anchore scan SARIF report
        uses: github/codeql-action/upload-sarif@v1
        with:
          sarif_file: ${{ steps.scan.outputs.sarif }}
```

Optionally, you can add a step to inspect the SARIF report produced:

```yaml
- name: Inspect action SARIF report
  run: cat ${{ steps.scan.outputs.sarif }}
```

## Contributing

We love contributions, feedback, and bug reports. For issues with the invocation of this action, file [issues](https://github.com/anchore/scan-action/issues) in this repository.

For contributing, see [Contributing](CONTRIBUTING.rst).

## More Information

For documentation on Grype itself, including other output capabilities, see the [grype project](https://github.com/anchore/grype)

Connect with the community directly on [slack](https://anchore.com/slack). These channels from Anchore's toolbox project are ideal for engaging development of help-related discussions:

- grype-dev
- grype-help

[test]: https://github.com/anchore/scan-action
[test-img]: https://github.com/anchore/scan-action/workflows/Tests/badge.svg
