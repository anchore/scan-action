require("@microsoft/jest-sarif"); // for sarif validation

const fs = require("fs");
const { runScan } = require("../index");

jest.setTimeout(90000); // 90 seconds; tests were timing out in CI. https://github.com/anchore/scan-action/pull/249

const testSource = async (source, vulnerabilities) => {
  if (fs.existsSync("./vulnerabilities.json")) {
    fs.unlinkSync("./vulnerabilities.json");
  }
  if (fs.existsSync("./results.sarif")) {
    fs.unlinkSync("./results.sarif");
  }

  const out = await runScan({
    source,
    failBuild: "false",
    outputFormat: "sarif",
    severityCutoff: "medium",
    onlyFixed: "false",
    addCpesIfNone: "false",
    byCve: "false",
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
      "anchore/test_images:alpine-package-cpe-vuln-match-bd0aaef@sha256:0825acea611c7c5cc792bc7cc20de44d7413fd287dc5afc4aab9c1891d037b4f",
      ["CVE-2022-37434-zlib", "CVE-2021-29921-python3"],
    );
    expect(sarif).toBeValidSarifLog();
  });
  it("centos", async () => {
    await testSource(
      "anchore/test_images:vulnerabilities-centos-stream9-ebc653b@sha256:3fa6909fa6f9a8ca8b7f9ba783af8cf84773c14084154073f1f331058ab646cb",
      ["CVE-2023-4911-glibc", "CVE-2024-28182-libnghttp2"],
    );
  });
  it("debian", async () => {
    const sarif = await testSource(
      "anchore/test_images:vulnerabilities-debian-56d52bc@sha256:7ed765e2d195dc594acc1c48fdda0daf7a44026cfb42372544cae1909de22adb",
      ["CVE-2022-37434-zlib1g", "CVE-2023-50387-libsystemd0"],
    );
    expect(sarif).toBeValidSarifLog();
  });
  it("npm", async () => {
    const sarif = await testSource("dir:tests/fixtures/npm-project", [
      "GHSA-3jfq-g458-7qm9-tar",
    ]);
    expect(sarif).toBeValidSarifLog();
  });
  it("yarn", async () => {
    const sarif = await testSource("dir:tests/fixtures/yarn-project", [
      "GHSA-w5p7-h5w8-2hfq-trim",
    ]);
    expect(sarif).toBeValidSarifLog();
  });
});
