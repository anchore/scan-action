import { describe, it } from "node:test";
import assert from "node:assert";
import { execSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import "./mocks.js"; // for runner env vars

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// these are smoke tests that the dist build was created correctly,
// functional tests should be in action.test.js
describe("scan-action dist build", () => {
  it("runs download-grype", () => {
    const { exitCode, stdout } = runDistBuild({
      run: "download-grype",
      sbom: "fixtures/test_sbom.spdx.json", // should be ignored
    });
    assert.equal(exitCode, 0);
    assert.match(stdout, /Downloaded Grype/);
    assert.doesNotMatch(stdout, /Failed minimum severity level/);
  });

  it("fails due to vulnerabilities found", () => {
    const { exitCode, stdout } = runDistBuild({
      image:
        "anchore/test_images:vulnerabilities-debian-56d52bc@sha256:7ed765e2d195dc594acc1c48fdda0daf7a44026cfb42372544cae1909de22adb",
    });
    assert.notEqual(exitCode, 0);
    assert.match(stdout, /Failed minimum severity level./);
  });

  it("runs with sbom", () => {
    const { exitCode, stdout } = runDistBuild({
      sbom: "tests/fixtures/test_sbom.spdx.json",
    });
    assert.notEqual(exitCode, 0);
    assert.match(stdout, /Failed minimum severity level./);
  });
});

// Execute the action, and return any outputs
function runDistBuild(inputs) {
  const repoRootDir = path.dirname(__dirname);
  const distPath = path.join(repoRootDir, "dist", "index.js");

  // Set up the environment variables
  const env = {
    HOME: process.env.HOME,
    PATH: process.env.PATH,
    // RUNNER_DEBUG: "1", // uncomment for debug logging
    RUNNER_TEMP: process.env.RUNNER_TEMP,
    RUNNER_TOOL_CACHE: process.env.RUNNER_TOOL_CACHE,
    GRYPE_DB_AUTO_UPDATE: "false",
    GRYPE_DB_VALIDATE_AGE: "false",
    GRYPE_DB_VALIDATE_BY_HASH_ON_START: "false",
    GRYPE_DB_REQUIRE_UPDATE_CHECK: "false",
    GRYPE_DB_MAX_ALLOWED_BUILT_AGE: "8760h", // 1 year
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
    stdout = execSync(`node ${distPath}`, {
      env,
    }).toString("utf8");
  } catch (error) {
    exitCode = error.status;
    stdout = `STDOUT: ${error.stdout.toString("utf8")}  \nSTDERR: ${error.stderr.toString("utf8")}`;
  }

  return {
    exitCode,
    stdout,
  };
}
