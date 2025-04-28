const githubActionsExec = require("@actions/exec");
const githubActionsToolCache = require("@actions/tool-cache");
const { mock, cleanup, mockIO } = require("./mocks");

jest.setTimeout(90000); // 90 seconds; tests were timing out in CI. https://github.com/anchore/scan-action/pull/249

describe("Grype command args", () => {
  afterEach(cleanup);

  it("is invoked with dir", async () => {
    const args = await mockRun({
      source: "dir:.",
      "fail-build": "false",
      "output-file": "the-output-file",
      "output-format": "sarif",
      "severity-cutoff": "high",
      version: "0.6.0",
      "only-fixed": "false",
      "add-cpes-if-none": "false",
      "by-cve": "false",
    });
    expect(args).toEqual([
      "-o",
      "sarif",
      "--file",
      "the-output-file",
      "--fail-on",
      "high",
      "dir:.",
    ]);
  });

  it("is invoked with cyclonedx output", async () => {
    const args = await mockRun({
      source: "dir:.",
      "fail-build": "false",
      "output-file": "the-output-file",
      "output-format": "cyclonedx-xml",
      "severity-cutoff": "high",
      version: "0.6.0",
      "only-fixed": "false",
      "add-cpes-if-none": "false",
      "by-cve": "false",
    });
    expect(args).toEqual([
      "-o",
      "cyclonedx-xml",
      "--file",
      "the-output-file",
      "--fail-on",
      "high",
      "dir:.",
    ]);
  });

  it("is invoked with cyclonedx-json output", async () => {
    const args = await mockRun({
      source: "dir:.",
      "fail-build": "false",
      "output-file": "the-output-file",
      "output-format": "cyclonedx-json",
      "severity-cutoff": "high",
      version: "0.6.0",
      "only-fixed": "false",
      "add-cpes-if-none": "false",
      "by-cve": "false",
    });
    expect(args).toEqual([
      "-o",
      "cyclonedx-json",
      "--file",
      "the-output-file",
      "--fail-on",
      "high",
      "dir:.",
    ]);
  });

  it("is invoked with values", async () => {
    const args = await mockRun({
      image: "asdf",
      "fail-build": "false",
      "output-file": "the-output-file",
      "output-format": "json",
      "severity-cutoff": "low",
      version: "0.6.0",
      "only-fixed": "false",
      "add-cpes-if-none": "false",
      "by-cve": "false",
    });
    expect(args).toEqual([
      "-o",
      "json",
      "--file",
      "the-output-file",
      "--fail-on",
      "low",
      "asdf",
    ]);
  });

  it("is invoked with config file", async () => {
    const args = await mockRun({
      image: "asdf",
      "fail-build": "false",
      "output-file": "the-output-file",
      "output-format": "json",
      "severity-cutoff": "low",
      version: "0.6.0",
      "only-fixed": "false",
      "add-cpes-if-none": "false",
      "by-cve": "false",
      "config-file-path": "path/to/config",
    });
    expect(args).toEqual([
      "-o",
      "json",
      "--file",
      "the-output-file",
      "--config",
      "path/to/config",
      "--fail-on",
      "low",
      "asdf",
    ]);
  });

  it("adds missing CPEs if requested", async () => {
    const args = await mockRun({
      image: "asdf",
      "fail-build": "false",
      "output-file": "the-output-file",
      "output-format": "json",
      "severity-cutoff": "low",
      version: "0.6.0",
      "only-fixed": "false",
      "add-cpes-if-none": "true",
      "by-cve": "false",
    });
    expect(args).toEqual([
      "-o",
      "json",
      "--file",
      "the-output-file",
      "--fail-on",
      "low",
      "--add-cpes-if-none",
      "asdf",
    ]);
  });

  it("adds VEX processing if requested", async () => {
    const args = await mockRun({
      image: "asdf",
      "fail-build": "false",
      "output-file": "the-output-file",
      "output-format": "json",
      "severity-cutoff": "low",
      version: "0.6.0",
      "only-fixed": "false",
      "add-cpes-if-none": "true",
      "by-cve": "false",
      vex: "test.vex",
    });
    expect(args).toEqual([
      "-o",
      "json",
      "--file",
      "the-output-file",
      "--fail-on",
      "low",
      "--add-cpes-if-none",
      "--vex",
      "test.vex",
      "asdf",
    ]);
  });

  it("with path by cve", async () => {
    const args = await mockRun({
      path: "asdf",
      "fail-build": "false",
      "output-file": "the-output-file",
      "output-format": "table",
      "severity-cutoff": "low",
      "by-cve": "true",
    });
    expect(args).toEqual([
      "-o",
      "table",
      "--file",
      "the-output-file",
      "--fail-on",
      "low",
      "--by-cve",
      "dir:asdf",
    ]);
  });
});

async function mockRun(inputs) {
  // don't bother downloading grype
  mock(githubActionsToolCache, {
    find() {
      return "grype";
    },
  });

  // track last exec calls args, pretend any call succeeds
  let callArgs;
  mock(githubActionsExec, {
    async exec(cmd, args) {
      callArgs = args;
      return 0;
    },
  });

  mockIO(inputs);

  try {
    const { run } = require("../index");
    await run();
  } catch (e) {
    e; // ignore: this happens trying to parse command output, which we don't care about
  }

  // get last invocation args, ignoring the grype binary part and -vv
  return (callArgs || []).filter((a) => a !== "-vv");
}
