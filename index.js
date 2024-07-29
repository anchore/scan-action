const tools = require("@actions/tool-cache");
const core = require("@actions/core");
const cache = require("@actions/cache");
const exec = require("@actions/exec");
const fs = require("fs");
const os = require("os");
const path = require("path");
const process = require("process");
const stream = require("stream");
const { GRYPE_VERSION } = require("./GrypeVersion");

const grypeVersion = core.getInput("grype-version") || GRYPE_VERSION;
const grypeExecutableName = isWindows() ? "grype.exe" : "grype";

async function downloadGrypeWindowsWorkaround(version) {
  const versionNoV = version.replace(/^v/, "");
  // example URL: https://github.com/anchore/grype/releases/download/v0.79.2/grype_0.79.2_windows_amd64.zip
  const url = `https://github.com/anchore/grype/releases/download/${version}/grype_${versionNoV}_windows_amd64.zip`;
  core.info(`Downloading grype from ${url}`);
  const zipPath = await tools.downloadTool(url);
  core.debug(`Zip saved to ${zipPath}`);
  const toolDir = await tools.extractZip(zipPath);
  core.debug(`Zip extracted to ${toolDir}`);
  const binaryPath = path.join(toolDir, grypeExecutableName);
  core.debug(`Grype path is ${binaryPath}`);
  return binaryPath;
}

function isWindows() {
  return process.platform === "win32";
}

/* download grype and return a path to the executable */
async function downloadGrype(version) {
  if (isWindows()) {
    return await downloadGrypeWindowsWorkaround(version);
  }

  const installScriptUrl = `https://raw.githubusercontent.com/anchore/grype/main/install.sh`;
  core.info(`Downloading grype ${version} via ${installScriptUrl}`);

  // TODO: when grype starts supporting unreleased versions, support it here
  // Download the installer, and run
  const installScriptPath = await tools.downloadTool(installScriptUrl);
  const installToDir = fs.mkdtempSync(
    path.join(os.tmpdir(), "grype-download-"),
  );

  const { stdout, exitCode } = await runCommand("sh", [
    installScriptPath,
    "-d",
    "-b",
    installToDir,
    version,
  ]);
  if (exitCode !== 0) {
    core.error("Error installing grype:");
    core.error(stdout);
    throw new Error("error installing grype");
  }
  return path.join(installToDir, isWindows() ? "grype.exe" : "grype");
}

async function installGrype(version) {
  core.info(`Installing grype ${version}`);

  let grypePath = tools.find(grypeExecutableName, version);
  if (!grypePath) {
    // Not found, install it
    grypePath = await downloadGrype(version);
    // Cache the downloaded file, get path to directory
    grypePath = await tools.cacheFile(
      grypePath,
      grypeExecutableName,
      grypeExecutableName,
      version,
    );
  }
  return path.join(grypePath, grypeExecutableName);
}

// Determines if multiple arguments are defined
function multipleDefined(...args) {
  let defined = false;
  for (const a of args) {
    if (defined && a) {
      return true;
    }
    if (a) {
      defined = true;
    }
  }
  return false;
}

function sourceInput() {
  const image = core.getInput("image");
  const path = core.getInput("path");
  const sbom = core.getInput("sbom");

  if (multipleDefined(image, path, sbom)) {
    throw new Error(
      "The following options are mutually exclusive: image, path, sbom",
    );
  }

  if (image) {
    return image;
  }

  if (sbom) {
    return "sbom:" + sbom;
  }

  if (!path) {
    // Default to the CWD
    return "dir:.";
  }

  return "dir:" + path;
}

async function run() {
  try {
    core.debug(new Date().toTimeString());
    // Grype accepts several input options, initially this action is supporting both `image` and `path`, so
    // a check must happen to ensure one is selected at least, and then return it
    const source = sourceInput();
    const failBuild = core.getInput("fail-build") || "true";
    const outputFormat = core.getInput("output-format") || "sarif";
    const severityCutoff = core.getInput("severity-cutoff") || "medium";
    const onlyFixed = core.getInput("only-fixed") || "false";
    const addCpesIfNone = core.getInput("add-cpes-if-none") || "false";
    const byCve = core.getInput("by-cve") || "false";
    const vex = core.getInput("vex") || "";
    const out = await runScan({
      source,
      failBuild,
      severityCutoff,
      onlyFixed,
      outputFormat,
      addCpesIfNone,
      byCve,
      vex,
    });
    Object.keys(out).map((key) => {
      core.setOutput(key, out[key]);
    });
  } catch (error) {
    core.setFailed(error.message);
  }
}

async function getDbDir(grypeCommand) {
  const { stdout } = await runCommand(
    grypeCommand,
    ["config", "--load"],
    process.env,
  );
  for (let line of stdout.split("\n")) {
    line = line.trim();
    if (line.startsWith("cache-dir:")) {
      line = line.replace("cache-dir:", "");
      line = line.replace("'~", os.homedir());
      line = line.replaceAll("'", "");
      line = line.trim();
      return line;
    }
  }
  throw new Error("unable to get grype db cache directory");
}

async function dbTime(grypeCommand) {
  const { stdout, exitCode } = await runCommand(
    grypeCommand,
    ["db", "status", "-vv"],
    process.env,
  );
  if (exitCode !== 0) {
    return;
  }
  for (let line of stdout.split("\n")) {
    line = line.trim();
    if (line.startsWith("Built:")) {
      line = line.replace("Built:", "");
      // 2024-07-25 01:30:47 +0000 UTC
      return new Date(line.trim());
    }
  }
}

async function updateDb(grypeCommand) {
  const { stdout, exitCode } = await runCommand(
    grypeCommand,
    ["db", "update", "-vv"],
    process.env,
  );
  if (exitCode !== 0) {
    throw new Error("unable to update db: " + stdout);
  }
}

// attempts to get an up-to-date database and from cache or update it,
// throws an exception if unable to get a database or use the cache
async function checkUpdateDbCache(grypeCommand) {
  if (!cache.isFeatureAvailable()) {
    throw new Error("cache not available");
  }

  const cachePrefix = `grype-db-${grypeVersion}-`;
  const cacheKey = cachePrefix + Date.now();

  const cacheDir = await getDbDir(grypeCommand);

  // match based on the cachePrefix but set values with a unique key to avoid conflicts when running in matrix builds
  // see: https://docs.github.com/en/actions/using-workflows/caching-dependencies-to-speed-up-workflows#matching-a-cache-key
  await cache.restoreCache([cacheDir], cacheKey, [cachePrefix], {}, true);

  const maxCachedDbMinutes =
    parseInt(core.getInput("db-cache-max-age")) || 60 * 24;
  const minAge = new Date();
  minAge.setMinutes(minAge.getMinutes() - maxCachedDbMinutes);

  const time = await dbTime(grypeCommand);
  if (time && time > minAge) {
    core.info(`Restored grype db from cache with age ${time}`);
    return; // do not need an update
  }

  // updateDb will throw an exception on error
  await updateDb(grypeCommand);

  core.debug(`Caching grype db`);

  // when saving cache, we want a completely unique cache key,
  // restore above will match based on the prefix if no exact match is found
  await cache.saveCache([cacheDir], cacheKey, {}, true);
}

async function runCommand(cmd, cmdArgs, env) {
  let stdout = "";

  // This /dev/null writable stream is required so the entire Grype output
  // is not written to the GitHub action log. the listener below
  // will actually capture the output
  const outStream = new stream.Writable({
    write(buffer, encoding, next) {
      next();
    },
  });

  const exitCode = await core.group(`${cmd} ${cmdArgs.join(" ")}`, () => {
    return exec.exec(cmd, cmdArgs, {
      env,
      ignoreReturnCode: true,
      outStream,
      listeners: {
        stdout(buffer) {
          stdout += buffer.toString();
        },
        stderr(buffer) {
          core.info(buffer.toString());
        },
        debug(message) {
          core.debug(message);
        },
      },
    });
  });

  core.debug(stdout);

  return { stdout, exitCode };
}

async function runScan({
  source,
  failBuild,
  severityCutoff,
  onlyFixed,
  outputFormat,
  addCpesIfNone,
  byCve,
  vex,
}) {
  const out = {};

  const env = {
    ...process.env,
    GRYPE_CHECK_FOR_APP_UPDATE: "false",
  };

  const registryUser = core.getInput("registry-username");
  const registryPass = core.getInput("registry-password");

  if (registryUser || registryPass) {
    env.GRYPE_REGISTRY_AUTH_USERNAME = registryUser;
    env.GRYPE_REGISTRY_AUTH_PASSWORD = registryPass;
    if (!registryUser || !registryPass) {
      core.warning(
        "WARNING: registry-username and registry-password must be specified together",
      );
    }
  }

  const SEVERITY_LIST = ["negligible", "low", "medium", "high", "critical"];
  const FORMAT_LIST = ["sarif", "json", "table"];
  let cmdArgs = [];

  if (core.isDebug()) {
    cmdArgs.push(`-vv`);
  }

  failBuild = failBuild.toLowerCase() === "true";
  onlyFixed = onlyFixed.toLowerCase() === "true";
  addCpesIfNone = addCpesIfNone.toLowerCase() === "true";
  byCve = byCve.toLowerCase() === "true";

  cmdArgs.push("-o", outputFormat);

  if (
    !SEVERITY_LIST.some(
      (item) =>
        typeof severityCutoff.toLowerCase() === "string" &&
        item === severityCutoff.toLowerCase(),
    )
  ) {
    throw new Error(
      `Invalid severity-cutoff value is set to ${severityCutoff} - please ensure you are choosing either negligible, low, medium, high, or critical`,
    );
  }
  if (
    !FORMAT_LIST.some(
      (item) =>
        typeof outputFormat.toLowerCase() === "string" &&
        item === outputFormat.toLowerCase(),
    )
  ) {
    throw new Error(
      `Invalid output-format value is set to ${outputFormat} - please ensure you are choosing either json or sarif`,
    );
  }

  core.debug(`Installing grype version ${grypeVersion}`);
  const grypeCommand = await installGrype(grypeVersion);

  let skipUpdate =
    `${process.env.GRYPE_DB_AUTO_UPDATE}`.toLowerCase() === "false";

  if (!skipUpdate) {
    try {
      await checkUpdateDbCache(grypeCommand);
      skipUpdate = true;
    } catch (e) {
      core.debug(
        `error from checkUpdateDbCache, falling back to db auto-update: ${e}`,
      );
      skipUpdate = false;
    }
  }

  if (skipUpdate) {
    env.GRYPE_DB_AUTO_UPDATE = "false";
  }

  core.debug("Source: " + source);
  core.debug("Fail Build: " + failBuild);
  core.debug("Severity Cutoff: " + severityCutoff);
  core.debug("Only Fixed: " + onlyFixed);
  core.debug("Add Missing CPEs: " + addCpesIfNone);
  core.debug("Orient by CVE: " + byCve);
  core.debug("Output Format: " + outputFormat);

  core.debug("Creating options for GRYPE analyzer");

  // Run the grype analyzer
  if (severityCutoff !== "") {
    cmdArgs.push("--fail-on");
    cmdArgs.push(severityCutoff.toLowerCase());
  }
  if (onlyFixed === true) {
    cmdArgs.push("--only-fixed");
  }
  if (addCpesIfNone === true) {
    cmdArgs.push("--add-cpes-if-none");
  }
  if (byCve === true) {
    cmdArgs.push("--by-cve");
  }
  if (vex) {
    cmdArgs.push("--vex");
    cmdArgs.push(vex);
  }
  cmdArgs.push(source);

  const { stdout, exitCode } = await runCommand(grypeCommand, cmdArgs, env);

  switch (outputFormat) {
    case "sarif": {
      const SARIF_FILE = "./results.sarif";
      fs.writeFileSync(SARIF_FILE, stdout);
      out.sarif = SARIF_FILE;
      break;
    }
    case "json": {
      const REPORT_FILE = "./results.json";
      fs.writeFileSync(REPORT_FILE, stdout);
      out.json = REPORT_FILE;
      break;
    }
    default: // e.g. table
      core.info(stdout);
  }

  // If there is a non-zero exit status code there are a couple of potential reporting paths
  if (exitCode > 0) {
    if (!severityCutoff) {
      // There was a non-zero exit status but it wasn't because of failing severity, this must be
      // a grype problem
      core.warning("grype had a non-zero exit status when running");
    } else if (failBuild === true) {
      core.setFailed(
        `Failed minimum severity level. Found vulnerabilities with level '${severityCutoff}' or higher`,
      );
    } else {
      // There is a non-zero exit status code with severity cut off, although there is still a chance this is grype
      // that is broken, it will most probably be a failed severity. Using warning here will make it bubble up in the
      // Actions UI
      core.warning(
        `Failed minimum severity level. Found vulnerabilities with level '${severityCutoff}' or higher`,
      );
    }
  }

  return out;
}

module.exports = {
  run,
  runScan,
  installGrype,
};

if (require.main === module) {
  const entrypoint = core.getInput("run");
  switch (entrypoint) {
    case "download-grype": {
      installGrype(grypeVersion).then((path) => {
        core.info(`Downloaded Grype to: ${path}`);
        core.setOutput("cmd", path);
      });
      break;
    }
    default: {
      run().then();
    }
  }
}
