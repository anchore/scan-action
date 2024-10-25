const githubActionsCore = require("@actions/core");
const githubActionsCache = require("@actions/cache");
const githubActionsExec = require("@actions/exec");
const { cleanup, mock, mockIO, setEnv, tmpdir, runAction } = require("./mocks");
const {
  sha256,
  tarGzDir,
  dbServer,
  listing,
  writeMetadata,
} = require("./db_server");
const { run } = require("../index");

jest.setTimeout(90000); // 90 seconds; tests were timing out in CI. https://github.com/anchore/scan-action/pull/249

describe("Github action", () => {
  afterEach(cleanup);

  it("runs with inputs requested", async () => {
    const requestedInputs = {};
    const expectedInputs = {
      image: "",
      path: "tests/fixtures/npm-project",
      "fail-build": "true",
      "output-format": "json",
      "severity-cutoff": "medium",
      "add-cpes-if-none": "true",
      vex: "test.vex",
    };

    mock(githubActionsCore, {
      getInput(name) {
        requestedInputs[name] = true;
        return expectedInputs[name];
      },
    });

    await run();

    Object.keys(expectedInputs).map((name) => {
      expect(requestedInputs[name]).toBeTruthy();
    });
  });

  it("runs with json report", async () => {
    const outputs = mockIO({
      image: "",
      path: "tests/fixtures/npm-project",
      "fail-build": "true",
      "output-format": "json",
      "severity-cutoff": "medium",
      "add-cpes-if-none": "true",
    });

    await run();

    expect(outputs["sarif"]).toBeFalsy();
    expect(outputs["json"]).toBe("./results.json");
  });

  it("runs with sarif report", async () => {
    const outputs = mockIO({
      image: "",
      path: "tests/fixtures/npm-project",
      "fail-build": "true",
      "output-format": "sarif",
      "severity-cutoff": "medium",
      "add-cpes-if-none": "true",
    });

    await run();

    expect(outputs["sarif"]).toBe("./results.sarif");
  });

  it("runs with table output", async () => {
    const { stdout, outputs } = await runAction({
      image: "localhost:5000/match-coverage/debian:latest",
      "fail-build": "true",
      "output-format": "table",
      "severity-cutoff": "medium",
      "add-cpes-if-none": "true",
    });

    expect(stdout).toContain("VULNERABILITY");

    expect(outputs["sarif"]).toBeFalsy();
    expect(outputs["json"]).toBeFalsy();
  });

  it("runs with cyclonedx output", async () => {
    const outputs = mockIO({
      image: "",
      path: "tests/fixtures/npm-project",
      "fail-build": "true",
      "output-format": "cyclonedx",
      "severity-cutoff": "medium",
      "add-cpes-if-none": "true",
    });

    await run();

    expect(outputs["cyclonedx"]).toBe("./results.bom");
  });

  it("runs with cyclonedx-json output", async () => {
    const outputs = mockIO({
      image: "",
      path: "tests/fixtures/npm-project",
      "fail-build": "true",
      "output-format": "cyclonedx-json",
      "severity-cutoff": "medium",
      "add-cpes-if-none": "true",
    });

    await run();

    expect(outputs["cyclonedx-json"]).toBe("./results.bom.json");
  });

  it("runs with environment variables", async () => {
    mockIO({
      path: "tests/fixtures/npm-project",
    });

    let call = {}; // commandLine, args, options

    const originalExec = githubActionsExec.exec;
    mock(githubActionsExec, {
      exec(commandLine, args, options) {
        call = {
          commandLine,
          args,
          options,
        };
        return originalExec(commandLine, args, options);
      },
    });

    setEnv({ BOGUS_ENVIRONMENT_VARIABLE: "bogus" });

    await run();

    expect(call.options).toBeDefined();
    expect(call.options.env.BOGUS_ENVIRONMENT_VARIABLE).toEqual("bogus");
  });

  it("errors with image and path", async () => {
    const { failure } = await runAction({
      image: "some-image",
      path: "some-path",
    });

    expect(failure).toContain(
      "The following options are mutually exclusive: image, path, sbom",
    );
  });

  it("errors with image and sbom", async () => {
    const { failure } = await runAction({
      image: "some-image",
      sbom: "some-sbom",
    });

    expect(failure).toContain(
      "The following options are mutually exclusive: image, path, sbom",
    );
  });

  it("errors with path and sbom", async () => {
    const { failure } = await runAction({
      path: "some-path",
      sbom: "some-image",
    });

    expect(failure).toContain(
      "The following options are mutually exclusive: image, path, sbom",
    );
  });

  it("fails due to vulnerabilities found", async () => {
    const { failure } = await runAction({
      image: "localhost:5000/match-coverage/debian:latest",
    });

    expect(failure).toContain("Failed minimum severity level.");
  });

  it("runs with sbom", async () => {
    const { failure } = await runAction({
      sbom: "fixtures/test_sbom.spdx.json",
    });

    expect(failure).toContain("Failed minimum severity level.");
  });

  it("uses db cache", async () => {
    const dbCacheRoot = tmpdir();

    mockIO({
      image: "localhost:5000/match-coverage/debian:latest", // scan with vulns
      path: "",
      "fail-build": "true",
      "output-format": "json",
      "severity-cutoff": "medium",
      "add-cpes-if-none": "true",
      "cache-db": "true",
    });

    let restoreCacheDir;
    let saveCacheDir;

    mock(githubActionsCache, {
      async isFeatureAvailable() {
        return true;
      },
      async restoreCache(...args) {
        restoreCacheDir = args[0][0];
      },
      async saveCache(...args) {
        saveCacheDir = args[0][0];
      },
    });

    const dbContents = await tarGzDir("grype-db/5");
    const dbChecksum = sha256(dbContents);
    const listings = [];

    // mock a listings file
    const listingResponse = {
      available: {
        5: listings,
      },
    };

    // mock the db update server
    const serverUrl = dbServer(listingResponse, dbContents);
    const listingUrl = serverUrl + "/listings.json";

    // set listing to have update
    listings.push(listing(new Date(), serverUrl + "/db.tar.gz", dbChecksum));

    setEnv({
      GRYPE_DB_CACHE_DIR: dbCacheRoot,
      GRYPE_DB_UPDATE_URL: listingUrl,
    });
    await run();

    expect(restoreCacheDir).toBe(dbCacheRoot);
    expect(saveCacheDir).toBe(dbCacheRoot);

    // with a current, fresh db, we should not have saveCache called
    restoreCacheDir = undefined;
    saveCacheDir = undefined;

    // update the db metadata to be fresh and not require an update
    const fresh = new Date();
    writeMetadata(dbCacheRoot, fresh);

    // env is already set to the tmpdir, with a fresh db
    await run();

    expect(restoreCacheDir).toBe(dbCacheRoot);
    expect(saveCacheDir).toBeUndefined();

    // update the db metadata to be > 24 hours
    const yesterday = new Date();
    yesterday.setHours(yesterday.getHours() - 24);
    writeMetadata(dbCacheRoot, yesterday);

    // reset call tracking
    restoreCacheDir = undefined;
    saveCacheDir = undefined;

    // env is already set to the tmpdir, but db is old and should be downloaded and cached
    await run();

    expect(restoreCacheDir).toBe(dbCacheRoot);
    expect(saveCacheDir).toBe(dbCacheRoot);
  });
});
