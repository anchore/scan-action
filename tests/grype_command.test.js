const githubActionsExec = require("@actions/exec");
const githubActionsToolCache = require("@actions/tool-cache");

jest.setTimeout(30000);

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
  it("is invoked with dir", async () => {
    let cmd = await mockExec({
      source: "dir:.",
      debug: "false",
      failBuild: "false",
      outputFormat: "sarif",
      severityCutoff: "high",
      version: "0.6.0",
      onlyFixed: "false",
    });
    expect(cmd).toBe("grype -o sarif --fail-on high dir:.");
  });

  it("is invoked with values", async () => {
    let cmd = await mockExec({
      source: "asdf",
      failBuild: "false",
      outputFormat: "json",
      severityCutoff: "low",
      version: "0.6.0",
      onlyFixed: "false",
    });
    expect(cmd).toBe("grype -o json --fail-on low asdf");
  });
});
