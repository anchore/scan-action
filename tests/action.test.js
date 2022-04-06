const child_process = require("child_process");
const os = require("os");
const path = require("path");
const process = require("process");

const actionPath = path.join(__dirname, "../dist/index.js");

// Execute the action, and return any outputs
function runAction(inputs) {
  // Set up the environment variables
  const env = {
    PATH: process.env.PATH,
    RUNNER_TEMP: process.env.RUNNER_TEMP,
    RUNNER_TOOL_CACHE: process.env.RUNNER_TOOL_CACHE,
  };
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
      .execSync(`node ${actionPath}`, {
        env,
      })
      .toString("utf8");
  } catch (error) {
    exitCode = error.status;
    stdout = error.stdout.toString("utf8");
  }

  const outputs = {
    exitCode,
    stdout,
  };

  // reverse setOutput command calls like:
  // ::set-output name=cmd::/tmp/actions/cache/grype/0.34.4/x64/grype
  for (const line of stdout.split(os.EOL)) {
    const groups = line.match(/::set-output name=(\w+)::(.*)$/);
    if (groups && groups.length > 2) {
      outputs[groups[1]] = groups[2];
    }
  }

  return outputs;
}

describe("scan-action", () => {
  it("runs download-grype", () => {
    const outputs = runAction({
      run: "download-grype",
    });
    expect(outputs.cmd).toBeDefined();
  });

  it("errors with invalid input", () => {
    let outputs = runAction({
      image: "some-image",
      path: "some-path",
    });
    expect(outputs.exitCode).toBe(1);
    expect(outputs.stdout).toContain(
      "The following options are mutually exclusive: image, path, sbom"
    );
    expect(outputs.stdout).not.toContain("grype");

    outputs = runAction({
      image: "some-image",
      sbom: "some-path",
    });
    expect(outputs.exitCode).toBe(1);
    expect(outputs.stdout).toContain(
      "The following options are mutually exclusive: image, path, sbom"
    );
    expect(outputs.stdout).not.toContain("grype");

    outputs = runAction({
      path: "some-path",
      sbom: "some-image",
    });
    expect(outputs.exitCode).toBe(1);
    expect(outputs.stdout).toContain(
      "The following options are mutually exclusive: image, path, sbom"
    );
    expect(outputs.stdout).not.toContain("grype");
  });

  it("fails due to vulnerabilities found", () => {
    const outputs = runAction({
      image: "localhost:5000/match-coverage/debian:latest",
    });
    expect(outputs.stdout).toContain("Failed minimum severity level.");
  });

  it("runs with sbom", () => {
    const outputs = runAction({
      sbom: "fixtures/test_sbom.spdx.json",
    });
    expect(outputs.stdout).toContain("Failed minimum severity level.");
  });
});
