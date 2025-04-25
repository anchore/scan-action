const githubActionsCore = require("@actions/core");
const githubActionsCache = require("@actions/cache");
const githubActionsExec = require("@actions/exec");
const { cleanup, mock, mockIO, setEnv, tmpdir, runAction } = require("./mocks");
const { run } = require("../index");

jest.setTimeout(90000); // 90 seconds; tests were timing out in CI. https://github.com/anchore/scan-action/pull/249

describe("Github action", () => {
  afterEach(cleanup);

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

    mock(githubActionsCore, {
      getInput(name) {
        requestedInputs[name] = true;
        return expectedInputs[name];
      },
      // ignore setFailed calls that set process.exitCode due to https://github.com/jestjs/jest/issues/14501
      setFailed() {},
    });

    await run();

    Object.keys(expectedInputs).map((name) => {
      expect(requestedInputs[name]).toBeTruthy();
    });
  });

  it("runs with json report", async () => {
    const outputs = mockIO({
      image: "",
      path: "tests/fixtures/npm-project",
      "fail-build": "true",
      "output-file": "./results.json",
      "output-format": "json",
      "severity-cutoff": "medium",
      "add-cpes-if-none": "true",
    });

    await run();

    expect(outputs["sarif"]).toBeFalsy();
    expect(outputs["json"]).toBe("./results.json");
  });

  it("runs with sarif report", async () => {
    const outputs = mockIO({
      image: "",
      path: "tests/fixtures/npm-project",
      "fail-build": "true",
      "output-file": "./results.sarif",
      "output-format": "sarif",
      "severity-cutoff": "medium",
      "add-cpes-if-none": "true",
    });

    await run();

    expect(outputs["sarif"]).toBe("./results.sarif");
  });

  it("runs with table output", async () => {
    const { stdout, outputs } = await runAction({
      image: "localhost:5000/match-coverage/debian:latest",
      "fail-build": "true",
      "output-format": "table",
      "severity-cutoff": "medium",
      "add-cpes-if-none": "true",
    });

    expect(stdout).toContain("VULNERABILITY");

    expect(outputs["sarif"]).toBeFalsy();
    expect(outputs["json"]).toBeFalsy();
  });

  it("runs with cyclonedx-xml output", async () => {
    const outputs = mockIO({
      image: "",
      path: "tests/fixtures/npm-project",
      "fail-build": "true",
      "output-format": "cyclonedx-xml",
      "output-file": "./results.cdx.xml",
      "severity-cutoff": "medium",
      "add-cpes-if-none": "true",
    });

    await run();

    expect(outputs["cyclonedx-xml"]).toBe("./results.cdx.xml");
  });

  it("runs with cyclonedx-json output", async () => {
    const outputs = mockIO({
      image: "",
      path: "tests/fixtures/npm-project",
      "fail-build": "true",
      "output-format": "cyclonedx-json",
      "severity-cutoff": "medium",
      "add-cpes-if-none": "true",
    });

    await run();

    expect(outputs["cyclonedx-json"]).toBeDefined();
  });

  it("runs with environment variables", async () => {
    mockIO({
      path: "tests/fixtures/npm-project",
    });

    let call = {}; // commandLine, args, options

    const originalExec = githubActionsExec.exec;
    mock(githubActionsExec, {
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

    expect(call.options).toBeDefined();
    expect(call.options.env.BOGUS_ENVIRONMENT_VARIABLE).toEqual("bogus");
  });

  it("errors with image and path", async () => {
    const { failure } = await runAction({
      image: "some-image",
      path: "some-path",
    });

    expect(failure).toContain(
      "The following options are mutually exclusive: image, path, sbom",
    );
  });

  it("errors with image and sbom", async () => {
    const { failure } = await runAction({
      image: "some-image",
      sbom: "some-sbom",
    });

    expect(failure).toContain(
      "The following options are mutually exclusive: image, path, sbom",
    );
  });

  it("errors with path and sbom", async () => {
    const { failure } = await runAction({
      path: "some-path",
      sbom: "some-image",
    });

    expect(failure).toContain(
      "The following options are mutually exclusive: image, path, sbom",
    );
  });

  it("fails due to vulnerabilities found", async () => {
    const { failure } = await runAction({
      image: "localhost:5000/match-coverage/debian:latest",
    });

    expect(failure).toContain("Failed minimum severity level.");
  });

  it("runs with sbom", async () => {
    const { failure } = await runAction({
      sbom: "fixtures/test_sbom.spdx.json",
    });

    expect(failure).toContain("Failed minimum severity level.");
  });
});
