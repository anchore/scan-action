[![Test Status][test-img]][test]

# GitHub Action for Anchore Container Scanning

This is a GitHub Action for invoking the [Anchore Engine](https://github.com/anchore/anchore-engine) scanner on a docker image and returning the vulnerabilities found,
manifest of contents found, and a pass/fail policy evaluation that can be used to fail the build if desired.

Use this in your workflows to verify the content of Docker containers after build and before pushing, allowing PRs, or deploying updates.

The action invokes the inline version of anchore engine, which is a script and docker image that run completely locally and
scan a local docker image and return the content, policy evaluation, and a final pass/fail status for the image.

**No data is sent to a remote service to execute the scan, and no credentials are required**

The vulnerability source data (from RedHat, Debian, Alpine, etc) is pre-baked into the container that is executed, so no
external fetch or initialization is necessary beyond pulling the container to execute. 

## Using the Action

### Getting the bill of materials only
By default, the action uses anchore engine to analyze the container and provide a listing of the packages found inside,
the vulnerabilities matched to those packages, and a policy evaluation recommendation. The job step will not fail the workflow
even if vulnerabilities are found.

In your workflow file, add a step:
```yaml
 - name: Scan image
   uses: anchore/scan-action@master
   with:
     image-reference: "localbuild/testimage:latest"
```

### Failing the build on policy and/or vulnerabilities
The above example will run the action but not cause the build to fail based on results. If you want to have the build step fail in cases where
there are vulnerabilities that violate the [default policy](dist/critical_security_policy.json) (fail only if vulnerabilities exist with severity >= HIGH and which have a fix available), then set the `fail-build` input = `true`.
That will make the job step fail of the policy evaluations detects a policy violation.

For example: 
```yaml
 - name: Scan image
   uses: anchore/scan-action@master
   with:
     image-reference: "localbuild/testimage:latest"
     fail-build: true
```

As a result of the action, you'll see some files in the `anchore-reports` directory in the workspace:

* `policy_evaluation.json` - Default anchore policy evaluation of the image
* `vulnerabilities.json` - Vulnerabilities found in the image
* `content.json` - packages (rpms, debs, npms, jars, gems, etc) found in the image, including versions, locations, and licenses

### Scanning Application Packages and OS Packages in the Container

By default, the action will only match vulnerabilities against OS/distro packages (rpms, dpkg, apk, etc). This is done
to allow the use of a much smaller scan image and thus faster scans. However, Anchore has the ability to match vulnerabilities
against npms, gems, python pip packages, and java (jars, wars, etc) as well. This scan will take longer, but produce a more
holistic view of the container vulnerability set. To enable this feature, set the 'include-app-packages' input parameter to 'true'.

For example:
```yaml
 - uses: anchore/scan-action@master
       with:
         image-reference: "localbuild/testimage:latest"
         dockerfile-path: "./Dockerfile"
         fail-build: true
         include-app-packages: true
```

### Supplying a Custom Policy

The default policy the action applies can fail the build if vulnerability with severity >= High is found that has a fix available.
To have other behavior, you can provide your own policy using the `custom-policy-path` parameter. The path is considered relative
to the root of the workspace (which gets reset to the repository if you use the `checkout` action).

For example, to include a custom policy as: .anchore/policy.json in your code repository, set:
```yaml
 - uses: anchore/scan-action@master
       with:
         image-reference: "localbuild/testimage:latest"
         dockerfile-path: "./Dockerfile"
         fail-build: true
         custom-policy-path: .anchore/policy.json
```

For an overview of policy format and the checks it can perform, see the [Anchore policy bundle documentation](https://docs.anchore.com/current/docs/engine/general/concepts/policy/bundles/)

### Action Inputs

| Input Name | Description | Required | Default Value |
|-----------------|-------------|----------|---------------|
| image-reference | The image to scan | :heavy_check_mark: | N/A |
| dockerfile-path | Path to a dockerfile used to build the image-reference image to add metadata for policy evaluation |  | null |
| debug | Verbose logging output |  | false |
| fail-build | Fail the build if policy evaluation returns a fail | | false |
| include-app-packages | Include application packages for vulnerability matches. Requires more vuln data and thus scan will be slower but better results | | false |
| custom-policy-path | A path to a policy json file for specifying a policy other than the default, which fails on >high vulnerabilities with fixes | | null |
| anchore-version | An optional parameter to specify a specific version of anchore to use for the scan. Default is the version locked to the scan-action release | false | v0.6.0 |
| acs-report-enable | Optionally, enable feature that causes a result.sarif report to be generated after successful action execution.  This report is compatible with GitHub Automated Code Scanning (ACS), as the artifact to upload for display as a Code Scanning Alert report. |
| acs-report-severity-cutoff | With ACS reporting enabled, optionally specify the minimum vulnerability severity to trigger an "error" level ACS result.  Valid choices are "Negligible", "Low", "Medium", "High" and "Critical".  Any vulnerability with a severity less than this value will lead to a "warning" result.  Default is "Medium". |

### Action Outputs 

| Output Name | Description | Type | 
|-----------------|-------------|----------|
| billofmaterials | Path to a json file with the list of packages found in the image | string |
| vulnerabilities | Path to a json file with list of vulnerabilities found in image | string |
| policycheck | Policy evaluation status of the image, either 'pass' or 'fail' | string |



### Example Workflows

Assuming your repository has a Dockerfile in the root directory:

```yaml
name: Docker Image CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v1
    - name: Build the Docker image
      run: docker build . --file Dockerfile --tag localbuild/testimage:latest
    - uses: anchore/scan-action@master
      with:
        image-reference: "localbuild/testimage:latest"
        dockerfile-path: "./Dockerfile"
        fail-build: true
    - name: anchore inline scan JSON results
      run: for j in `ls ./anchore-reports/*.json`; do echo "---- ${j} ----"; cat ${j}; echo; done
```

Same example as above, but with Automated Code Scanning (ACS) feature enabled - with this example, the action will generate a SARIF report, which can be uploaded and then displayed as a Code Scanning Report in the GitHub UI.

```yaml
name: Docker Image CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v1
    - name: Build the Docker image
      run: docker build . --file Dockerfile --tag localbuild/testimage:latest
    - uses: anchore/scan-action@master
      with:
        image-reference: "localbuild/testimage:latest"
        dockerfile-path: "./Dockerfile"
        fail-build: true
        acs-report-enable: true
        #acs-report-severity-cutoff: "Medium"
    - name: anchore inline scan JSON results
      run: for j in `ls ./anchore-reports/*.json`; do echo "---- ${j} ----"; cat ${j}; echo; done
    - name: anchore action SARIF report
      run: cat results.sarif
    - name: upload Anchore scan SARIF report
      uses: Anthophila/codeql-action/codeql/upload-sarif@master
      with:
        sarif_file: results.sarif
```

## Contributing

We love contributions, feedback, and bug reports. For issues with the invocation of this action, file [issues](https://github.com/anchore/anchore-scan-action/issues) in this repository.

For contributing, see [Contributing](CONTRIBUTING.rst).


## More Information
For documentation on Anchore itself, including policy language and capabilities see the [Anchore Documentation](https://docs.anchore.com)

Connect with the anchore community directly on [slack](https://anchore.com/slack).

[test]: https://github.com/anchore/scan-action
[test-img]: https://github.com/anchore/scan-action/workflows/Tests/badge.svg
