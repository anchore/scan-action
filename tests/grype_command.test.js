const githubActionsExec = require("@actions/exec");
const githubActionsToolCache = require("@actions/tool-cache");

jest.setTimeout(30000);

jest.spyOn(githubActionsToolCache, "find").mockImplementation(() => {
  return "grype";
});

const spyExec = jest.spyOn(githubActionsExec, "exec").mockImplementation(() => {
  return Promise.resolve();
});

const { runScan } = require("../index");

const mockExec = async (args) => {
  await runScan(args);
  const [cmd, params] = spyExec.mock.calls[spyExec.mock.calls.length - 1];
  return `${cmd} ${params.join(" ")}`;
};

describe("Grype command", () => {
  it("is invoked with defaults", async () => {
    let cmd = await mockExec({ source: "python:3.8" });
    expect(cmd).toBe("grype -o json --fail-on medium python:3.8");
  });

  it("is invoked with dir", async () => {
    let cmd = await mockExec({ source: "dir:.", severityCutoff: "high" });
    expect(cmd).toBe("grype -o json --fail-on high dir:.");
  });

  it("is invoked with values", async () => {
    let cmd = await mockExec({
      source: "asdf",
      debug: "true",
      failBuild: "false",
      acsReportEnable: "false",
      severityCutoff: "low",
      version: "0.6.0",
    });
    expect(cmd).toBe("grype -vv -o json --fail-on low asdf");
  });
});
