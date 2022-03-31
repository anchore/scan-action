const child_process = require("child_process");
const os = require("os");
const path = require("path");
const process = require("process");

const actionPath = path.join(__dirname, "../index.js");

// Execute the action, and return any outputs
function runAction(inputs) {
  // reverse core.js: const val = process.env[`INPUT_${name.replace(/ /g, '_').toUpperCase()}`] || '';
  for (const k in inputs) {
    process.env[`INPUT_${k}`.toUpperCase()] = inputs[k];
  }
  // capture stdout
  const stdout = child_process
    .execSync(`node ${actionPath}`, {
      env: process.env,
    })
    .toString("utf8");
  const outputs = {};
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

describe("sbom-action", () => {
  it("runs download-grype", () => {
    const outputs = runAction({
      run: "download-grype",
    });
    expect(outputs.cmd).toBeDefined();
  });
});
