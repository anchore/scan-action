import { describe, it } from "node:test";
import assert from "node:assert";
import { mock, mockIO, run } from "./mocks.js";

describe(
  "Grype command args",
  { timeout: 90000 /* 90 seconds seems to be sufficient time for /ci */ },
  () => {
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
      assert.deepEqual(args, [
        "-v",
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
      assert.deepEqual(args, [
        "-v",
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
      assert.deepEqual(args, [
        "-v",
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
      assert.deepEqual(args, [
        "-v",
        "-o",
        "json",
        "--file",
        "the-output-file",
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
      assert.deepEqual(args, [
        "-v",
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
      assert.deepEqual(args, [
        "-v",
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
      assert.deepEqual(args, [
        "-v",
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

    it("adds single config file if specified", async () => {
      const args = await mockRun({
        image: "asdf",
        "fail-build": "false",
        "output-file": "the-output-file",
        "output-format": "json",
        "severity-cutoff": "low",
        "only-fixed": "false",
        "add-cpes-if-none": "false",
        "by-cve": "false",
        config: ".grype-custom.yaml",
      });
      assert.deepEqual(args, [
        "-v",
        "-o",
        "json",
        "--file",
        "the-output-file",
        "--fail-on",
        "low",
        "-c",
        ".grype-custom.yaml",
        "asdf",
      ]);
    });

    it("adds multiple config files if specified", async () => {
      const args = await mockRun({
        image: "asdf",
        "fail-build": "false",
        "output-file": "the-output-file",
        "output-format": "json",
        "severity-cutoff": "low",
        "only-fixed": "false",
        "add-cpes-if-none": "false",
        "by-cve": "false",
        config: "base.yaml\noverrides.yaml",
      });
      assert.deepEqual(args, [
        "-v",
        "-o",
        "json",
        "--file",
        "the-output-file",
        "--fail-on",
        "low",
        "-c",
        "base.yaml",
        "-c",
        "overrides.yaml",
        "asdf",
      ]);
    });
  },
);

async function mockRun(inputs) {
  // don't bother downloading grype
  await mock("@actions/tool-cache", {
    find() {
      return "grype";
    },
  });

  // track last exec call args, pretend any call succeeds
  let callArgs;
  await mock("@actions/exec", {
    async exec(cmd, args) {
      callArgs = args;
      return 0;
    },
  });

  await mockIO(inputs);

  try {
    await run();
  } catch {
    // ignore: this happens trying to parse command output, which we don't care about
  }

  // get last invocation args, ignoring the grype binary part and -vv
  return (callArgs || []).filter((a) => a !== "-vv");
}
