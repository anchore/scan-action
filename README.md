# GitHub Action for Anchore Scan

This is a GitHub Action for invoking the <a href="https://github.com/anchore/anchore-engine">Anchore Engine</a> scanner on a docker image and returning the vulnerabilities found,
manifest of contents found, and a pass/fail policy evaluation that can be used to fail the build if desired.

<a href="https://github.com/anchore/anchore-scan-action"><img alt="GitHub Actions status" src="https://github.com/anchore/anchore-scan-action/workflows/Tests/badge.svg"></a>

## Action parameters

See [`action.yml`](action.yml) for the input, outputs and configuration.

## Using the Action

### Getting the bill of materials only
By default, the action uses anchore engine to analyze the container and provide a listing of the packages found inside,
the vulnerabilities matched to those packages, and a policy evaluation recommendation. The job step will not fail the workflow
even if vulnerabilities are found.

In your workflow file, add a step:
```yaml
 - name: Scan image
   uses: anchore/anchore-scan-action@master
   with:
     image-reference: "localbuild/testimage:latest"
```

### Failing the build on policy and/or vulnerabilities
The above example will run the action but not cause the build to fail based on results. If you want to have the build step fail in cases where
there are vulnerabilities that violate the [default policy](dist/critical_security_policy.json) (fail only if vulnerabilities exist with severity >= HIGH and which have a fix available), then set the `fail_build` input = `true`.
That will make the job step fail of the policy evaluations detects a policy violation.

For example: 
```yaml
 - name: Scan image
   uses: anchore/anchore-scan-action@master
   with:
     image-reference: "localbuild/testimage:latest"
     fail-build: true
```

As a result of the action, you'll see some files in the `anchore-reports` directory in the workspace:

* `policy_evaluation.json` - Default anchore policy evaluation of the image
* `vulnerabilities.json` - Vulnerabilities found in the image
* `content-os.json` - OS packages (rpms, debs, etc) found in the image

### Scanning Application Packages and OS Packages in the Container

By default, the action will only match vulnerabilities against OS/distro packages (rpms, dpkg, apk, etc). This is done
to allow the use of a much smaller scan image and thus faster scans. However, Anchore has the ability to match vulnerabilities
against npms, gems, python pip packages, and java (jars, wars, etc) as well. This scan will take longer, but produce a more
holistic view of the container vulnerability set. To enable this feature, set the 'include-app-packages' input parameter to 'true'.

For example:
```yaml
 - uses: anchore/anchore-scan-action@master
       with:
         image-reference: "localbuild/testimage:latest"
         dockerfile-path: "./Dockerfile"
         fail-build: true
         include-app-package: true
```


### Example Workflow

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
    - uses: anchore/anchore-scan-action@master
      with:
        image-reference: "localbuild/testimage:latest"
        dockerfile-path: "./Dockerfile"
        fail-build: true
    - name: anchore inline scan JSON results
      run: for j in `ls ./anchore-reports/*.json`; do echo "---- ${j} ----"; cat ${j}; echo; done
```
