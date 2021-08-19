const { run } = require("../index");
const core = require("@actions/core");

jest.setTimeout(30000);

describe("Github action args", () => {
  it("runs without sarif report", async () => {
    const inputs = {
      image: "",
      path: "tests/fixtures/npm-project",
      debug: "false",
      "fail-build": "true",
      "acs-report-enable": "false",
      "severity-cutoff": "medium",
      "grype-version": "",
    };
    const spyInput = jest.spyOn(core, "getInput").mockImplementation((name) => {
      try {
        return inputs[name];
      } finally {
        inputs[name] = true;
      }
    });

    const outputs = {};
    const spyOutput = jest
      .spyOn(core, "setOutput")
      .mockImplementation((name, value) => {
        outputs[name] = value;
      });

    await run();

    Object.keys(inputs).map((name) => {
      expect(inputs[name]).toBe(true);
    });

    expect(outputs["vulnerabilities"]).toBe("./vulnerabilities.json");
    expect(outputs["sarif"]).toBeFalsy();

    spyInput.mockRestore();
    spyOutput.mockRestore();
  });

  it("runs with sarif report", async () => {
    const inputs = {
      image: "",
      path: "tests/fixtures/npm-project",
      debug: "false",
      "fail-build": "true",
      "acs-report-enable": "true",
      "severity-cutoff": "medium",
      "grype-version": "",
    };
    const spyInput = jest.spyOn(core, "getInput").mockImplementation((name) => {
      try {
        return inputs[name];
      } finally {
        inputs[name] = true;
      }
    });

    const outputs = {};
    const spyOutput = jest
      .spyOn(core, "setOutput")
      .mockImplementation((name, value) => {
        outputs[name] = value;
      });

    await run();

    Object.keys(inputs).map((name) => {
      expect(inputs[name]).toBe(true);
    });

    expect(outputs["vulnerabilities"]).toBe("./vulnerabilities.json");
    expect(outputs["sarif"]).toBe("./results.sarif");

    spyInput.mockRestore();
    spyOutput.mockRestore();
  });
});
