# GitHub Action for Anchore Scan

**WORK IN PROGRESS**

This is a GitHub Action for invoking the Anchore Engine scanner on a docker image and returning some artifacts.

## Action parameters

See [action.yml](action.yml) for the input section and configuration.

## Using the Action

In your workflow.yaml, add a step:
```
 - uses: zhill/anchore-scan-action@master
      with:
        image_reference: "localbuild/testimage:latest"
```

As a result of the action, in your workspace you'll see some files in the `anchore-reports` directory in the workspace:

* _policy_evaluation.json_ - Default anchore policy evaluation of the image
* _vulnerabilities.json_ - Vulnerabilities found in the image
* _summary.json_ - Image metadata summary (distro etc)
* _content-os.json_ - OS packages (rpms, debs, etc) found in the image
* _content-java.json_ - Java packages (jars, wars, etc) found in the image
* _content-gem.json_ - Ruby Gems found in the image
* _content-python.json_ - Python PyPi packages found in the image
* _content-npm.json_ - npms packages found in the image

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
        image_reference: "localbuild/testimage:12345"
        dockerfile_path: "./Dockerfile"
    - name: anchore inline scan JSON results
      run: for j in `ls ./anchore-reports/*.json`; do echo "---- ${j} ----"; cat ${j}; echo; done
```
