import { describe, it } from "node:test";
import assert from "node:assert";
import { mock } from "./mocks.js";
import { GRYPE_VERSION } from "../GrypeVersion.js";

let imports = 0;

// installs grype with the download and exec calls mocked out, returning the
// installer URL that was fetched and the environment the installer ran with
async function mockInstall(version) {
  let downloadedUrl;
  await mock("@actions/tool-cache", {
    find() {
      return "";
    },
    downloadTool(url) {
      downloadedUrl = url;
      return "install-script-path";
    },
    cacheFile() {
      return "grype";
    },
  });

  let env;
  await mock("@actions/exec", {
    async exec(cmd, args, options) {
      env = options.env;
      return 0;
    },
  });

  // a fresh copy of the module, so it picks up the mocks above
  const { installGrype } = await import(`../action.js?i=${imports++}`);
  await installGrype(version);

  return { downloadedUrl, env };
}

describe("installing grype", () => {
  it("treats only whole release tags as pinnable", async () => {
    const { isReleaseTag } = await import("../action.js");

    for (const version of ["v0.114.0", "v0.1.0", "v1.0.0-rc.1"]) {
      assert.ok(isReleaseTag(version), `expected '${version}' to be a tag`);
    }
    // the version ends up in the URL of a script that gets executed, so
    // anything that could point at another repository has to be rejected
    for (const version of [
      "latest",
      "0.114.0",
      "main",
      "v0.114.0/../../../someone/else/main",
      "v1/../../../someone/else/main",
    ]) {
      assert.ok(
        !isReleaseTag(version),
        `expected '${version}' not to be a tag`,
      );
    }
  });

  it("downloads the installer pinned to the grype release tag", async () => {
    const { downloadedUrl, env } = await mockInstall(GRYPE_VERSION);

    assert.equal(
      downloadedUrl,
      `https://raw.githubusercontent.com/anchore/grype/${GRYPE_VERSION}/install.sh`,
    );
    // otherwise the installer would fetch and run an unpinned copy of itself
    assert.equal(env.DOWNLOAD_TAG_INSTALL_SCRIPT, "false");
  });

  it("falls back to the default branch for a version that is not a tag", async () => {
    const { downloadedUrl, env } = await mockInstall("latest");

    assert.equal(
      downloadedUrl,
      "https://raw.githubusercontent.com/anchore/grype/main/install.sh",
    );
    // the installer resolves "latest" itself and fetches its tagged version
    assert.equal(env.DOWNLOAD_TAG_INSTALL_SCRIPT, "true");
  });
});
