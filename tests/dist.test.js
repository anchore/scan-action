const child_process = require("child_process");
const path = require("path");

// these are smoke tests that the dist build was created correctly,
// functional tests should be in action.test.js
describe("scan-action dist build", () => {
  it("runs download-grype", () => {
    const { stdout } = runDistBuild({
      run: "download-grype",
      sbom: "fixtures/test_sbom.spdx.json", // should be ignored
    });
    expect(stdout).toContain("Downloaded Grype");
    expect(stdout).not.toContain("Failed minimum severity level.");
  });

  it("fails due to vulnerabilities found", () => {
    const { stdout } = runDistBuild({
      image:
        "anchore/test_images:vulnerabilities-debian-56d52bc@sha256:7ed765e2d195dc594acc1c48fdda0daf7a44026cfb42372544cae1909de22adb",
    });
    expect(stdout).toContain("Failed minimum severity level.");
  });

  it("runs with sbom", () => {
    const { stdout } = runDistBuild({
      sbom: "fixtures/test_sbom.spdx.json",
    });
    expect(stdout).toContain("Failed minimum severity level.");
  });
});

// Execute the action, and return any outputs
function runDistBuild(inputs) {
  const repoRootDir = path.dirname(__dirname);
  const distPath = path.join(repoRootDir, "dist", "index.js");

  // Set up the environment variables
  const env = {
    PATH: process.env.PATH,
    RUNNER_TEMP: process.env.RUNNER_TEMP,
    RUNNER_TOOL_CACHE: process.env.RUNNER_TOOL_CACHE,
    GRYPE_DB_AUTO_UPDATE: "false",
    GRYPE_DB_VALIDATE_AGE: "false",
  };
  // this is brittle and may need to be updated, but is currently how input are passed to the process:
  // reverse core.js: const val = process.env[`INPUT_${name.replace(/ /g, '_').toUpperCase()}`] || '';
  for (const k in inputs) {
    // NOTE: there is a bug with node exec where environment variables with dashes
    // are not always preserved - we will just have to rely on defaults in the code
    env[`INPUT_${k}`.toUpperCase()] = inputs[k];
  }

  // capture stdout and exit code, and execute the command
  let exitCode = 0;
  let stdout;
  try {
    stdout = child_process
      .execSync(`node ${distPath}`, {
        env,
      })
      .toString("utf8");
  } catch (error) {
    exitCode = error.status;
    stdout = error.stdout.toString("utf8");
  }

  return {
    exitCode,
    stdout,
  };
}
