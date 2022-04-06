const cache = require("@actions/tool-cache");
const core = require("@actions/core");
const { exec } = require("@actions/exec");
const fs = require("fs");
const stream = require("stream");
const { GRYPE_VERSION } = require("./GrypeVersion");

const grypeBinary = "grype";
const grypeVersion = core.getInput("grype-version") || GRYPE_VERSION;

async function downloadGrype(version) {
  let url = `https://raw.githubusercontent.com/anchore/grype/main/install.sh`;

  core.debug(`Installing ${version}`);

  // TODO: when grype starts supporting unreleased versions, support it here
  // Download the installer, and run
  const installPath = await cache.downloadTool(url);
  // Make sure the tool's executable bit is set
  await exec(`chmod +x ${installPath}`);

  let cmd = `${installPath} -b ${installPath}_grype ${version}`;
  await exec(cmd);
  let grypePath = `${installPath}_grype/grype`;

  // Cache the downloaded file
  return cache.cacheFile(grypePath, `grype`, `grype`, version);
}

async function installGrype(version) {
  let grypePath = cache.find(grypeBinary, version);
  if (!grypePath) {
    // Not found, install it
    grypePath = await downloadGrype(version);
  }

  // Add tool to path for this and future actions to use
  core.addPath(grypePath);
  return `${grypePath}/${grypeBinary}`;
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
  var image = core.getInput("image");
  var path = core.getInput("path");
  var sbom = core.getInput("sbom");

  if (multipleDefined(image, path, sbom)) {
    throw new Error(
      "The following options are mutually exclusive: image, path, sbom"
    );
  }

  if (!(image || path || sbom)) {
    throw new Error(
      "At least one source for scanning needs to be provided. Available options are: image, path and sbom"
    );
  }

  if (image !== "") {
    return image;
  }

  if (sbom !== "") {
    return "sbom:" + sbom;
  }

  return "dir:" + path;
}

async function run() {
  try {
    core.debug(new Date().toTimeString());
    // Grype accepts several input options, initially this action is supporting both `image` and `path`, so
    // a check must happen to ensure one is selected at least, and then return it
    const source = sourceInput();
    const debug = core.getInput("debug") || "false";
    const failBuild = core.getInput("fail-build") || "true";
    const acsReportEnable = core.getInput("acs-report-enable") || "true";
    const severityCutoff = core.getInput("severity-cutoff") || "medium";
    const out = await runScan({
      source,
      debug,
      failBuild,
      acsReportEnable,
      severityCutoff,
    });
    Object.keys(out).map((key) => {
      core.setOutput(key, out[key]);
    });
  } catch (error) {
    core.setFailed(error.message);
  }
}

async function runScan({
  source,
  debug,
  failBuild,
  acsReportEnable,
  severityCutoff,
}) {
  const out = {};

  const SEVERITY_LIST = ["negligible", "low", "medium", "high", "critical"];
  let cmdArgs = [];

  if (debug.toLowerCase() === "true") {
    debug = "true";
    cmdArgs.push(`-vv`);
  } else {
    debug = "false";
  }

  failBuild = failBuild.toLowerCase() === "true";

  acsReportEnable = acsReportEnable.toLowerCase() === "true";

  if (acsReportEnable) {
    cmdArgs.push("-o", "sarif");
  } else {
    cmdArgs.push("-o", "json");
  }

  if (
    !SEVERITY_LIST.some(
      (item) =>
        typeof severityCutoff.toLowerCase() === "string" &&
        item === severityCutoff.toLowerCase()
    )
  ) {
    throw new Error(
      `Invalid severity-cutoff value is set to ${severityCutoff} - please ensure you are choosing either negligible, low, medium, high, or critical`
    );
  }

  core.debug(`Installing grype version ${grypeVersion}`);
  await installGrype(grypeVersion);

  core.debug("Source: " + source);
  core.debug("Debug Output: " + debug);
  core.debug("Fail Build: " + failBuild);
  core.debug("Severity Cutoff: " + severityCutoff);
  core.debug("ACS Enable: " + acsReportEnable);

  core.debug("Creating options for GRYPE analyzer");

  // Run the grype analyzer
  let cmdOutput = "";
  let cmd = `${grypeBinary}`;
  if (severityCutoff !== "") {
    cmdArgs.push("--fail-on");
    cmdArgs.push(severityCutoff.toLowerCase());
  }
  cmdArgs.push(source);

  // This /dev/null writable stream is required so the entire Grype output
  // is not written to the GitHub action log. the listener below
  // will actually capture the output
  const outStream = new stream.Writable({
    write(buffer, encoding, next) {
      next();
    },
  });

  core.info("\nAnalyzing: " + source);

  core.info(`Executing: ${cmd} ` + cmdArgs.join(" "));

  const exitCode = await core.group(`${cmd} output...`, async () =>
    exec(cmd, cmdArgs, {
      ignoreReturnCode: true,
      outStream,
      listeners: {
        stdout(buffer) {
          cmdOutput += buffer.toString();
        },
        stderr(buffer) {
          core.info(buffer.toString());
        },
        debug(message) {
          core.debug(message);
        },
      },
    })
  );

  if (core.isDebug()) {
    core.debug("Grype output:");
    core.debug(cmdOutput);
  }

  if (acsReportEnable) {
    const SARIF_FILE = "./results.sarif";
    fs.writeFileSync(SARIF_FILE, cmdOutput);
    out.sarif = SARIF_FILE;
  }

  if (failBuild === true && exitCode > 0) {
    core.setFailed(
      `Failed minimum severity level. Found vulnerabilities with level ${severityCutoff} or higher`
    );
  }

  // If there is a non-zero exit status code there are a couple of potential reporting paths
  if (failBuild === false && exitCode > 0) {
    // There was a non-zero exit status but it wasn't because of failing severity, this must be
    // a grype problem
    if (!severityCutoff) {
      core.warning("grype had a non-zero exit status when running");
    } else {
      // There is a non-zero exit status code with severity cut off, although there is still a chance this is grype
      // that is broken, it will most probably be a failed severity. Using warning here will make it bubble up in the
      // Actions UI
      core.warning(
        `Failed minimum severity level. Found vulnerabilities with level ${severityCutoff} or higher`
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
