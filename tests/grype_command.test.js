const githubActionsExec = require("@actions/exec");
const githubActionsToolCache = require("@actions/tool-cache");
const core = require("@actions/core");

jest.setTimeout(90000); // 90 seconds; tests were timing out in CI. https://github.com/anchore/scan-action/pull/249

jest.spyOn(githubActionsToolCache, "find").mockImplementation(() => {
  return "grype";
});

const spyExec = jest.spyOn(githubActionsExec, "exec").mockImplementation(() => {
  return Promise.resolve(0);
});

const mockExec = async (args) => {
  try {
    const { runScan } = require("../index");
    await runScan(args);
  } catch (e) {
    // ignore: this happens trying to parse command output, which we don't care about
  }
  const [cmd, params] = spyExec.mock.calls[spyExec.mock.calls.length - 1];
  return `${cmd} ${params.join(" ")}`;
};

describe("Grype command", () => {
  const cmdPrefix = core.isDebug() ? "grype -vv" : "grype";

  it("is invoked with dir", async () => {
    let cmd = await mockExec({
      source: "dir:.",
      failBuild: "false",
      outputFormat: "sarif",
      severityCutoff: "high",
      version: "0.6.0",
      onlyFixed: "false",
      addCpesIfNone: "false",
      byCve: "false",
    });
    expect(cmd).toBe(`${cmdPrefix} -o sarif --fail-on high dir:.`);
  });

  it("is invoked with values", async () => {
    let cmd = await mockExec({
      source: "asdf",
      failBuild: "false",
      outputFormat: "json",
      severityCutoff: "low",
      version: "0.6.0",
      onlyFixed: "false",
      addCpesIfNone: "false",
      byCve: "false",
    });
    expect(cmd).toBe(`${cmdPrefix} -o json --fail-on low asdf`);
  });

  it("adds missing CPEs if requested", async () => {
    let cmd = await mockExec({
      source: "asdf",
      failBuild: "false",
      outputFormat: "json",
      severityCutoff: "low",
      version: "0.6.0",
      onlyFixed: "false",
      addCpesIfNone: "true",
      byCve: "false",
    });
    expect(cmd).toBe(
      `${cmdPrefix} -o json --fail-on low --add-cpes-if-none asdf`
    );
  });

  it("adds VEX processing if requested", async () => {
    let cmd = await mockExec({
      source: "asdf",
      failBuild: "false",
      outputFormat: "json",
      severityCutoff: "low",
      version: "0.6.0",
      onlyFixed: "false",
      addCpesIfNone: "true",
      byCve: "false",
      vex: "test.vex",
    });
    expect(cmd).toBe(
      `${cmdPrefix} -o json --fail-on low --add-cpes-if-none --vex test.vex asdf`
    );
  });
});
