require("@microsoft/jest-sarif"); // for sarif validation

const fs = require("fs");
const { runScan } = require("../index");

jest.setTimeout(30000);

const testSource = async (source, vulnerabilities) => {
  if (fs.existsSync("./vulnerabilities.json")) {
    fs.rmSync("./vulnerabilities.json");
  }
  if (fs.existsSync("./results.sarif")) {
    fs.rmSync("./results.sarif");
  }

  const out = await runScan({
    source,
    acsReportEnable: "true",
  });

  // expect to get sarif output
  const sarifFile = fs.readFileSync(out.sarif, "utf8");
  expect(sarifFile).not.toBeNull();

  // expect the sarif to be valid
  const sarif = JSON.parse(sarifFile);
  expect(sarif).toBeValidSarifLog();

  // expect to find some known error-level vulnerability
  if (vulnerabilities.length === 0) {
    expect(sarif.runs[0].results.length).toBe(0);
  } else {
    vulnerabilities.forEach((vuln) => {
      expect(sarif.runs[0].results.find((r) => r.ruleId === vuln)).toBeTruthy();
    });
  }
};

describe("SARIF", () => {
  it("alpine", async () => {
    await testSource("localhost:5000/match-coverage/alpine:latest", [
      "ANCHOREVULN_CVE-2014-6051_apk_libvncserver_0.9.9",
    ]);
  });
  it("centos", async () => {
    await testSource("localhost:5000/match-coverage/centos:latest", []);
  });
  it("debian", async () => {
    await testSource("localhost:5000/match-coverage/debian:latest", [
      "ANCHOREVULN_CVE-2020-36327_gem_bundler_2.1.4",
      "ANCHOREVULN_GHSA-9w8r-397f-prfh_python_Pygments_2.6.1",
    ]);
  });
  it("npm", async () => {
    await testSource("dir:tests/fixtures/npm-project", [
      "ANCHOREVULN_GHSA-3jfq-g458-7qm9_npm_tar_6.1.0",
    ]);
  });
  it("yarn", async () => {
    await testSource("dir:tests/fixtures/yarn-project", [
      "ANCHOREVULN_GHSA-w5p7-h5w8-2hfq_npm_trim_0.0.2",
    ]);
  });
});
