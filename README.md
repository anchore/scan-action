# GitHub Action for Anchore Scan

**WORK IN PROGRESS**

This is a GitHub Action for invoking the Anchore Engine scanner on a docker image and returning some artifacts.

<a href="https://github.com/anchore/anchore-scan-action"><img alt="GitHub Actions status" src="https://github.com/anchore/anchore-scan-action/workflows/Tests/badge.svg"></a>

## Action parameters

See [`action.yml`](action.yml) for the input section and configuration.

## Using the Action

In your `workflow.yaml`, add a step:
```yaml
 - name: Scan image
   uses: anchore/anchore-scan-action@master
   with:
     image_reference: "localbuild/testimage:latest"
```

As a result of the action, you'll see some files in the `anchore-reports` directory in the workspace:

* `policy_evaluation.json` - Default anchore policy evaluation of the image
* `vulnerabilities.json` - Vulnerabilities found in the image
* `summary.json` - Image metadata summary (distro etc)
* `content-os.json` - OS packages (rpms, debs, etc) found in the image
* `content-java.json` - Java packages (jars, wars, etc) found in the image
* `content-gem.json` - Ruby Gems found in the image
* `content-python.json` - Python PyPi packages found in the image
* `content-npm.json` - npm packages found in the image

### Example Workflow
```
name: Docker Image CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v1
    - name: Build the Docker image
      run: docker build . --file Dockerfile --tag localbuild/testimage:12345
    - uses: anchore/anchore-scan-action@master
      with:
        image-reference: "localbuild/testimage:12345"
        dockerfile-path: "./Dockerfile"
    - name: anchore inline scan JSON results
      run: for j in `ls ./anchore-reports/*.json`; do echo "---- ${j} ----"; cat ${j}; echo; done
```
