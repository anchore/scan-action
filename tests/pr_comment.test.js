import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  parseSarifForComment,
  buildPrCommentBody,
  postPrComment,
} from "../action.js";

// A small but realistic grype SARIF report (shape taken from real grype output).
const sampleSarif = {
  runs: [
    {
      tool: {
        driver: {
          rules: [
            {
              id: "CVE-2022-1111-openssl",
              helpUri: "https://example.com/CVE-2022-1111",
              help: {
                text: "Vulnerability CVE-2022-1111\nSeverity: critical\nPackage: openssl\nVersion: 1.1.1\nFix Version: 1.1.1n",
              },
            },
            {
              id: "GHSA-aaaa-tar",
              helpUri: "https://example.com/GHSA-aaaa",
              help: {
                text: "Vulnerability GHSA-aaaa\nSeverity: high\nPackage: tar\nVersion: 6.1.0\nFix Version: 6.1.1",
              },
            },
          ],
        },
      },
      results: [
        { ruleId: "CVE-2022-1111-openssl", level: "error" },
        { ruleId: "GHSA-aaaa-tar", level: "error" },
      ],
    },
  ],
};

describe("parseSarifForComment", () => {
  it("extracts fields from grype help text", () => {
    const vulns = parseSarifForComment(sampleSarif);
    assert.equal(vulns.length, 2);
    assert.deepEqual(vulns[0], {
      id: "CVE-2022-1111",
      severity: "critical",
      package: "openssl",
      version: "1.1.1",
      fix: "1.1.1n",
      link: "https://example.com/CVE-2022-1111",
    });
  });

  it("returns an empty list for an empty or malformed report", () => {
    assert.deepEqual(parseSarifForComment({}), []);
    assert.deepEqual(parseSarifForComment(null), []);
  });
});

describe("buildPrCommentBody", () => {
  it("includes the marker so comments can be updated in place", () => {
    assert.match(
      buildPrCommentBody([]),
      /<!-- anchore\/scan-action pr-comment -->/,
    );
  });

  it("reports a clean result when there are no vulnerabilities", () => {
    assert.match(buildPrCommentBody([]), /No vulnerabilities found/);
  });

  it("summarizes counts and sorts most severe first", () => {
    const body = buildPrCommentBody(parseSarifForComment(sampleSarif));
    assert.match(body, /Found 2 vulnerabilities \(1 critical, 1 high\)/);
    assert.ok(
      body.indexOf("openssl") < body.indexOf("tar"),
      "critical row should appear before high row",
    );
    assert.match(
      body,
      /\[CVE-2022-1111\]\(https:\/\/example\.com\/CVE-2022-1111\)/,
    );
  });
});

describe("postPrComment", () => {
  function eventFile(payload) {
    const p = path.join(
      fs.mkdtempSync(path.join(os.tmpdir(), "pr-comment-test-")),
      "event.json",
    );
    fs.writeFileSync(p, JSON.stringify(payload));
    return p;
  }

  const baseEnv = (eventPath) => ({
    GITHUB_EVENT_NAME: "pull_request",
    GITHUB_REPOSITORY: "octo/repo",
    GITHUB_EVENT_PATH: eventPath,
  });

  it("skips when the event is not a pull request", async () => {
    const calls = [];
    await postPrComment({
      token: "t",
      body: "b",
      env: { GITHUB_EVENT_NAME: "push" },
      api: (...args) => calls.push(args),
    });
    assert.equal(calls.length, 0);
  });

  it("skips when no token is provided", async () => {
    const calls = [];
    await postPrComment({
      token: "",
      body: "b",
      env: baseEnv(eventFile({ pull_request: { number: 5 } })),
      api: (...args) => calls.push(args),
    });
    assert.equal(calls.length, 0);
  });

  it("creates a new comment when none exists", async () => {
    const calls = [];
    const api = (token, method, apiPath, body) => {
      calls.push({ method, apiPath, body });
      return method === "GET" ? [] : {};
    };
    await postPrComment({
      token: "t",
      body: "hello",
      env: baseEnv(eventFile({ pull_request: { number: 5 } })),
      api,
    });
    const post = calls.find((c) => c.method === "POST");
    assert.ok(post, "expected a POST to create a comment");
    assert.equal(post.apiPath, "/repos/octo/repo/issues/5/comments");
    assert.equal(post.body.body, "hello");
  });

  it("updates the existing marked comment instead of creating a new one", async () => {
    const calls = [];
    const api = (token, method, apiPath, body) => {
      calls.push({ method, apiPath, body });
      return method === "GET"
        ? [{ id: 42, body: "old <!-- anchore/scan-action pr-comment --> body" }]
        : {};
    };
    await postPrComment({
      token: "t",
      body: "updated",
      env: baseEnv(eventFile({ pull_request: { number: 7 } })),
      api,
    });
    const patch = calls.find((c) => c.method === "PATCH");
    assert.ok(patch, "expected a PATCH to update the comment");
    assert.equal(patch.apiPath, "/repos/octo/repo/issues/comments/42");
    assert.ok(!calls.find((c) => c.method === "POST"), "should not POST");
  });
});
