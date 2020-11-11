# Release Notes

## Version 2.0.2 - 2020-11-11

* Update `actions/core` to use version `1.2.6` [(Issue #71)](https://github.com/anchore/scan-action/issues/71)

## Version 2.0.1 - 2020-02-11

Fixes:

* Removes unnecessary constraint in deduplication for SARIF reporting
* Allows defining and referencing the location of the SARIF report file
* Fixes multiple instances where undefined items in the reporting would break scanning


## Version 2.0.0 - 2020-30-09

2.0.0 is a new major version of scan action based on the new [Grype](https://github.com/anchore/grype) tool from Anchore.
It is much faster for scanning compared to v1.x of the action and adds some new capabilities, including directory scanning as well as container image scanning,
and also has more metadata about the vulnerability matches than previous versions for more transparency on the matching process.

Improvements and Changes:

* Significantly faster performance for scans
* New vulnerabilities output format is the JSON output from Grype directly
* Adds support for scanning directories as well as Docker containers, so you can do the same checks pre-and post-build of the container.
* Supports Automatic Code Scanning/SARIF for exposing results via your repository's Security tab.
* Updated the default branch from `master` to `main`

*NOTE: This is a breaking change from v1.x, as indicated by the major version change. We strongly recommend using a @v2 or specific version instead of @main*

Breaking Changes for v2:

* Inputs:
  * Changed `image-reference` to `image` (required)
  * `dockerfile-path` is no longer supported and not necessary for the vulnerability scans
  * `custom-policy-path` is no longer supported
  * `include-app-packages` is no longer necessary or supported. Application packages are on by default and will receive vulnerability matches.
* Outputs:
  * `billofmaterials` is no longer output. V2 is focused on vulnerability scanning and another action may be introduced for BoM support with its own options/config.
  * `policycheck` is no longer output
