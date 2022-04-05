const child_process = require("child_process");
const os = require("os");
const path = require("path");
const process = require("process");

const actionPath = path.join(__dirname, "../index.js");

// Execute the action, and return any outputs
function runAction(inputs) {
  // set defaults:
  const env = {
    "fail-build": "true",
    "acs-report-enable": "true",
    "severity-cutoff": "medium",
  };
  // reverse core.js: const val = process.env[`INPUT_${name.replace(/ /g, '_').toUpperCase()}`] || '';
  for (const k in inputs) {
    env[`INPUT_${k}`.toUpperCase()] = inputs[k];
  }
  // capture stdout
  let exitCode = 0;
  let stdout;
  try {
    stdout = child_process
      .execSync(`node ${actionPath}`, {
        env: Object.assign(env, process.env),
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
    const outputs = runAction({
      image: "some-image",
      path: "some-path",
    });
    expect(outputs.exitCode).toBe(1);
    expect(outputs.stdout).toContain(
      "Cannot use both 'image' and 'path' as sources"
    );
    expect(outputs.stdout).not.toContain("grype");
  });

  it("fails due to vulnerabilities found", () => {
    const outputs = runAction({
      image: "localhost:5000/match-coverage/debian:latest",
      "severity-cutoff": "medium",
    });
    expect(outputs.stdout).toContain(
      "Failed minimum severity level. Found vulnerabilities with level medium or higher"
    );
  });
});
