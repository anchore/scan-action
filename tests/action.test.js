import { describe, it } from "node:test";
import assert from "node:assert";
import { mockIO, setEnv, run, mock, runCapturing } from "./mocks.js";

describe("Github action", () => {
  it("runs with inputs requested", async () => {
    const requestedInputs = {};
    const expectedInputs = {
      image: "",
      path: "tests/fixtures/npm-project",
      "fail-build": "true",
      "output-format": "json",
      "severity-cutoff": "medium",
      "add-cpes-if-none": "true",
      vex: "test.vex",
    };

    await mock("@actions/core", {
      getInput(name) {
        requestedInputs[name] = true;
        return expectedInputs[name];
      },
      // ignore setFailed calls that set process.exitCode due to https://github.com/jestjs/jest/issues/14501
      setFailed() {},
    });

    await run();

    Object.keys(expectedInputs).forEach((name) => {
      assert.ok(
        requestedInputs[name],
        `expected input "${name}" to be requested`,
      );
    });
  });

  it("runs with json report", async () => {
    const outputs = await mockIO({
      image: "",
      path: "tests/fixtures/npm-project",
      "fail-build": "true",
      "output-file": "./results.json",
      "output-format": "json",
      "severity-cutoff": "medium",
      "add-cpes-if-none": "true",
    });

    await run();

    assert.ok(!outputs["sarif"]);
    assert.equal(outputs["json"], "./results.json");
  });

  it("runs with sarif report", async () => {
    const outputs = await mockIO({
      image: "",
      path: "tests/fixtures/npm-project",
      "fail-build": "true",
      "output-file": "./results.sarif",
      "output-format": "sarif",
      "severity-cutoff": "medium",
      "add-cpes-if-none": "true",
    });

    await run();

    assert.equal(outputs["sarif"], "./results.sarif");
  });

  it("runs with table output", async () => {
    const { stdout, outputs } = await runCapturing({
      image:
        "anchore/test_images:vulnerabilities-debian-56d52bc@sha256:7ed765e2d195dc594acc1c48fdda0daf7a44026cfb42372544cae1909de22adb",
      "fail-build": "true",
      "output-format": "table",
      "severity-cutoff": "medium",
      "add-cpes-if-none": "true",
    });

    assert.ok(stdout.includes("VULNERABILITY"));

    assert.ok(!outputs["sarif"]);
    assert.ok(!outputs["json"]);
  });

  it("runs with cyclonedx-xml output", async () => {
    const outputs = await mockIO({
      image: "",
      path: "tests/fixtures/npm-project",
      "fail-build": "true",
      "output-format": "cyclonedx-xml",
      "output-file": "./results.cdx.xml",
      "severity-cutoff": "medium",
      "add-cpes-if-none": "true",
    });

    await run();

    assert.equal(outputs["cyclonedx-xml"], "./results.cdx.xml");
  });

  it("runs with cyclonedx-json output", async () => {
    const outputs = await mockIO({
      image: "",
      path: "tests/fixtures/npm-project",
      "fail-build": "true",
      "output-format": "cyclonedx-json",
      "severity-cutoff": "medium",
      "add-cpes-if-none": "true",
    });

    await run();

    assert.ok(outputs["cyclonedx-json"]);
  });

  it("runs with environment variables", async () => {
    await mockIO({
      path: "tests/fixtures/npm-project",
    });

    let call = {}; // commandLine, args, options

    const { originalExec } = await import("@actions/exec");
    await mock("@actions/exec", {
      exec(commandLine, args, options) {
        call = {
          commandLine,
          args,
          options,
        };
        return originalExec(commandLine, args, options);
      },
    });

    setEnv({ BOGUS_ENVIRONMENT_VARIABLE: "bogus" });

    await run();

    assert.ok(call.options);
    assert.equal(call.options.env.BOGUS_ENVIRONMENT_VARIABLE, "bogus");
  });

  it("errors with image and path", async () => {
    const { failure } = await runCapturing({
      image: "some-image",
      path: "some-path",
    });

    assert.match(
      failure,
      /The following options are mutually exclusive: image, path, sbom/,
    );
  });

  it("errors with image and sbom", async () => {
    const { failure } = await runCapturing({
      image: "some-image",
      sbom: "some-sbom",
    });

    assert.match(
      failure,
      /The following options are mutually exclusive: image, path, sbom/,
    );
  });

  it("errors with path and sbom", async () => {
    const { failure } = await runCapturing({
      path: "some-path",
      sbom: "some-image",
    });

    assert.match(
      failure,
      /The following options are mutually exclusive: image, path, sbom/,
    );
  });

  it("fails due to vulnerabilities found", async () => {
    const { failure } = await runCapturing({
      image:
        "anchore/test_images:vulnerabilities-debian-56d52bc@sha256:7ed765e2d195dc594acc1c48fdda0daf7a44026cfb42372544cae1909de22adb",
    });

    assert.match(failure, /Failed minimum severity level./);
  });

  it("runs with sbom", async () => {
    const { failure } = await runCapturing({
      sbom: "tests/fixtures/test_sbom.spdx.json",
    });

    assert.match(failure, /Failed minimum severity level./);
  });

  it("outputs errors", async () => {
    const { stdout } = await runCapturing({
      sbom: "tests/fixtures/test_sbom.spdx.json",
      vex: "missing-file",
    });

    assert.match(stdout, /VEX document "missing-file" not found/);
  });
});
