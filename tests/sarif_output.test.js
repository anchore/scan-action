require("@microsoft/jest-sarif"); // for sarif validation

const fs = require("fs");
const { runScan } = require("../index");

jest.setTimeout(30000);

const testSource = async (source, vulnerabilities) => {
  if (fs.existsSync("./vulnerabilities.json")) {
    fs.unlinkSync("./vulnerabilities.json");
  }
  if (fs.existsSync("./results.sarif")) {
    fs.unlinkSync("./results.sarif");
  }

  const out = await runScan({
    source,
    debug: "false",
    failBuild: "false",
    outputFormat: "sarif",
    severityCutoff: "medium",
    onlyFixed: "false",
  });

  // expect to get sarif output
  const sarifFile = fs.readFileSync(out.sarif, "utf8");
  expect(sarifFile).not.toBeNull();

  // expect the sarif to be valid
  const sarif = JSON.parse(sarifFile);
  expect(sarif).toBeValidSarifLog();

  if (sarif.runs && sarif.runs.length > 0) {
    sarif.runs[0].tool.driver.version = "";
  }

  for (let run of sarif.runs || []) {
    for (let result of run.results || []) {
      for (let loc of result.locations || []) {
        for (let l of loc.logicalLocations || []) {
          l.fullyQualifiedName = "";
        }
      }
    }
  }

  // expect to find some known error-level vulnerability
  if (vulnerabilities.length === 0) {
    expect(sarif.runs[0].results.length).toBe(0);
  } else {
    vulnerabilities.forEach((vuln) => {
      expect(sarif.runs[0].results.find((r) => r.ruleId === vuln)).toBeTruthy();
    });
  }

  return sarif;
};

describe("SARIF", () => {
  it("alpine", async () => {
    const sarif = await testSource(
      "localhost:5000/match-coverage/alpine:latest",
      ["CVE-2014-6051-libvncserver"]
    );
    expect(sarif).toMatchSnapshot();
  });
  it("centos", async () => {
    await testSource("localhost:5000/match-coverage/centos:latest", []);
  });
  it("debian", async () => {
    const sarif = await testSource(
      "localhost:5000/match-coverage/debian:latest",
      ["CVE-2020-36327-bundler", "GHSA-9w8r-397f-prfh-Pygments"]
    );
    expect(sarif).toMatchSnapshot();
  });
  it("npm", async () => {
    const sarif = await testSource("dir:tests/fixtures/npm-project", [
      "GHSA-3jfq-g458-7qm9-tar",
    ]);
    expect(sarif).toMatchSnapshot();
  });
  it("yarn", async () => {
    const sarif = await testSource("dir:tests/fixtures/yarn-project", [
      "GHSA-w5p7-h5w8-2hfq-trim",
    ]);
    expect(sarif).toMatchSnapshot();
  });
});
