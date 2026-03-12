import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { execSync } from "node:child_process";
import fs from "node:fs";
import { runScan } from "../action.js";
import "./mocks.js"; // for runner env vars

function assertValidSarif(sarif) {
  const sarifString = JSON.stringify(sarif);
  try {
    const result = execSync(
      "docker run --rm -i ghcr.io/anchore/sarif-validator:0.1.0@sha256:a0729d695e023740f5df6bcb50d134e88149bea59c63a896a204e88f62b564c6",
      { input: sarifString },
    );
    assert.match(result.toString(), /sarif-validator@0.0.0 test/);
  } catch (error) {
    if (process.env.CI === "true" && process.platform === "darwin") {
      assert.skip("Skipping due to no docker on macos in CI");
      return;
    }
    assert.fail(`SARIF validation failed:
     STATUS: ${error.status}
     MESSAGE: ${error.message}
     STDOUT: ${error.stdout.toString()}
     STDERR: ${error.stderr.toString()}`);
  }
}

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
  assert.ok(sarifFile, "SARIF file should not be empty");

  // expect the sarif to be valid
  const sarif = JSON.parse(sarifFile);
  assertValidSarif(sarif);

  if (sarif.runs && sarif.runs.length > 0) {
    sarif.runs[0].tool.driver.version = "";
  }

  for (const run of sarif.runs || []) {
    for (const result of run.results || []) {
      for (const loc of result.locations || []) {
        for (const l of loc.logicalLocations || []) {
          l.fullyQualifiedName = "";
        }
      }
    }
  }

  // expect to find some known error-level vulnerability
  if (vulnerabilities.length === 0) {
    assert.equal(sarif.runs[0].results.length, 0);
  } else {
    vulnerabilities.forEach((vuln) => {
      assert.ok(
        sarif.runs[0].results.find((r) => r.ruleId === vuln),
        `expected to find vulnerability ${vuln}`,
      );
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
    assertValidSarif(sarif);
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
    assertValidSarif(sarif);
  });
  it("npm", async () => {
    const sarif = await testSource("dir:tests/fixtures/npm-project", [
      "GHSA-3jfq-g458-7qm9-tar",
    ]);
    assertValidSarif(sarif);
  });
  it("yarn", async () => {
    const sarif = await testSource("dir:tests/fixtures/yarn-project", [
      "GHSA-w5p7-h5w8-2hfq-trim",
    ]);
    assertValidSarif(sarif);
  });
});
