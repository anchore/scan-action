const cache = require("@actions/tool-cache");
const core = require("@actions/core");
const { exec } = require("@actions/exec");
const fs = require("fs");

const grypeBinary = "grype";
const grypeVersion = "0.16.0";

// sarif code
function convert_severity_to_acs_level(input_severity, severity_cutoff_param) {
  // The `severity_cutoff_param` has been lowercased for case-insensitivity at this point, but the
  // severity from the vulnerability will be capitalized, so this must be capitalized again to calculate
  // using the same object
  let param =
    severity_cutoff_param[0].toUpperCase() + severity_cutoff_param.substring(1);
  var ret = "error";
  const severityLevels = {
    Unknown: 0,
    Negligible: 1,
    Low: 2,
    Medium: 3,
    High: 4,
    Critical: 5,
  };

  if (severityLevels[input_severity] < severityLevels[param]) {
    ret = "warning";
  }

  return ret;
}

function getLocation(v) {
  if (v.artifact.locations.length) {
    // If the scan was against a directory, the location will be a string
    var location = v.artifact.locations[0];
    if (typeof location === "string") {
      return location;
    }
    // Otherwise it is an object with "path" and "layer" keys
    return location["path"];
  }
  // XXX there is room for improvement here, trying to mimick previous behavior
  // If no `dockerfile-path` was provided, and in the improbable situation where there
  // are no locations for the artifact, return 'Dockerfile'
  return "Dockerfile";
}

function textMessage(v) {
  const path = getLocation(v);
  var scheme = sourceScheme();
  let prefix = `The path ${path} reports ${v.artifact.name} at version ${v.artifact.version} `;

  if (["dir", "tar"].includes(scheme)) {
    return `${prefix} which would result in a vulnerable (${v.artifact.type}) package installed`;
  } else {
    return `${prefix} which is a vulnerable (${v.artifact.type}) package installed in the container`;
  }
}

function dottedQuadFileVersion(version) {
  // The dotted quad version requirements of the SARIF schema has some strict requirements. Because
  // it is tied to the version which can be (optionally) set by the user, it isn't enough to blindly
  // add a trailing ".0" - This function validates the end result, falling back to a version that would
  // pass the schema while issuing a warning.
  const pattern = /[0-9]+(\.[0-9]+){3}/;
  // grype has some releases with dashes, ensure these are pruned
  version = version.split("-")[0];

  // None of the Grype versions will ever have version with four parts, add a trailing `.0` here
  version = version + ".0";

  if (!version.match(pattern)) {
    // After prunning and adding a trailing .0 we still got a failure. Warn about this, and fallback to
    // a made-up version guaranteed to work.
    core.warning(
      `Unable to produce an acceptable four-part dotted version: ${version} \n` +
        `SARIF reporting requires pattern matching against "[0-9]+(\\.[0-9]+){3}" \n` +
        "Will fallback to 0.0.0.0"
    );
    return "0.0.0.0";
  }
  return version;
}

function get_fix_versions(v) {
  if (
    v.vulnerability.fix &&
    v.vulnerability.fix.state === "fixed" &&
    v.vulnerability.fix.versions &&
    v.vulnerability.fix.versions.length > 0
  ) {
    return v.vulnerability.fix.versions.join(",");
  }
  return "";
}

function make_subtitle(v) {
  let subtitle = `${v.vulnerability.description}`;
  if (subtitle != "undefined") {
    return subtitle;
  }

  const fixVersions = get_fix_versions(v);
  if (fixVersions) {
    return `Version ${v.artifact.version} is affected with an available fix in versions ${fixVersions}`;
  }

  return `Version ${v.artifact.version} is affected with no fixes reported yet.`;
}

function grype_render_rules(vulnerabilities, source) {
  var ret = {};
  let scheme = sourceScheme();
  if (vulnerabilities) {
    let ruleIDs = [];
    // This uses .reduce() because there can be duplicate vulnerabilities which the SARIF schema complains about.
    ret = vulnerabilities.reduce(function (result, v) {
      let ruleID = `ANCHOREVULN_${v.vulnerability.id}_${v.artifact.type}_${v.artifact.name}_${v.artifact.version}`;
      if (scheme == "docker") {
        // include the container as part of the rule id so that users can sort by that
        ruleID = `ANCHOREVULN_${source}_${v.vulnerability.id}_${v.artifact.type}_${v.artifact.name}_${v.artifact.version}`;
      }

      if (!ruleIDs.includes(ruleID)) {
        ruleIDs.push(ruleID);
        // Entirely possible to not have any links whatsoever
        let link = v.vulnerability.id;
        if ("dataSource" in v.vulnerability) {
          link = `[${v.vulnerability.id}](${v.vulnerability.dataSource})`;
        } else if (
          "urls" in v.vulnerability &&
          v.vulnerability.urls.length > 0
        ) {
          link = `[${v.vulnerability.id}](${v.vulnerability.urls[0]})`;
        }

        result.push({
          id: ruleID,
          // Title of the SARIF report
          shortDescription: {
            text: `${v.vulnerability.id} ${v.vulnerability.severity} vulnerability for ${v.artifact.name} package`,
          },
          // Subtitle of the SARIF report
          fullDescription: {
            text: make_subtitle(v),
          },
          help: {
            text:
              "Vulnerability " +
              v.vulnerability.id +
              "\n" +
              "Severity: " +
              v.vulnerability.severity +
              "\n" +
              "Package: " +
              v.artifact.name +
              "\n" +
              "Version: " +
              v.artifact.version +
              "\n" +
              "Fix Version: " +
              (get_fix_versions(v) || "none") +
              "\n" +
              "Type: " +
              v.artifact.type +
              "\n" +
              "Location: " +
              v.artifact.locations[0].path +
              "\n" +
              //"Data Namespace: "+v.vulnerability.matched_by.matcher +"\n"+
              "Data Namespace: " +
              "unknown" +
              "\n" +
              `Link: ${link}`,
            markdown:
              "**Vulnerability " +
              v.vulnerability.id +
              "**\n" +
              "| Severity | Package | Version | Fix Version | Type | Location | Data Namespace | Link |\n" +
              "| --- | --- | --- | --- | --- | --- | --- | --- |\n" +
              "|" +
              v.vulnerability.severity +
              "|" +
              v.artifact.name +
              "|" +
              v.artifact.version +
              "|" +
              (get_fix_versions(v) || "none") +
              "|" +
              v.artifact.type +
              "|" +
              v.artifact.locations[0].path +
              "|" +
              "unknown" +
              "|" +
              link +
              "|\n",
          },
        });
      }
      return result;
    }, []);
  }
  return ret;
}

function grype_render_results(vulnerabilities, severity_cutoff_param, source) {
  var ret = {};
  let scheme = sourceScheme();
  if (vulnerabilities) {
    ret = vulnerabilities.map((v) => {
      let ruleid = `ANCHOREVULN_${v.vulnerability.id}_${v.artifact.type}_${v.artifact.name}_${v.artifact.version}`;
      if (scheme == "docker") {
        // include the container as part of the rule id so that users can sort by that
        ruleid = `ANCHOREVULN_${source}_${v.vulnerability.id}_${v.artifact.type}_${v.artifact.name}_${v.artifact.version}`;
      }
      return {
        ruleId: ruleid,
        ruleIndex: 0,
        level: convert_severity_to_acs_level(
          v.vulnerability.severity,
          severity_cutoff_param
        ),
        message: {
          text: textMessage(v),
          id: "default",
        },
        analysisTarget: {
          uri: getLocation(v),
          // XXX This is possibly a bug. The SARIF schema invalidates this when the index is present because there
          // aren't any other elements present.
          //"index": 0
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: {
                uri: getLocation(v),
              },
              // TODO: When grype starts reporting line numbers this will need to get updated
              region: {
                startLine: 1,
                startColumn: 1,
                endLine: 1,
                endColumn: 1,
                byteOffset: 1,
                byteLength: 1,
              },
            },
            logicalLocations: [
              {
                fullyQualifiedName: "dockerfile",
              },
            ],
          },
        ],
        suppressions: [
          {
            kind: "external",
          },
        ],
        baselineState: "unchanged",
      };
    });
  }

  return ret;
}

function vulnerabilities_to_sarif(
  grypeVulnerabilities,
  severity_cutoff_param,
  version,
  source
) {
  let vulnerabilities = grypeVulnerabilities.matches;

  const sarifOutput = {
    $schema:
      "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.4.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Anchore Container Vulnerability Report (T0)",
            fullName: "Anchore Container Vulnerability Report (T0)",
            version: version,
            semanticVersion: version,
            dottedQuadFileVersion: dottedQuadFileVersion(version),
            rules: grype_render_rules(vulnerabilities, source),
          },
        },
        logicalLocations: [
          {
            name: "dockerfile",
            fullyQualifiedName: "dockerfile",
            kind: "namespace",
          },
        ],
        results: grype_render_results(
          vulnerabilities,
          severity_cutoff_param,
          source
        ),
        columnKind: "utf16CodeUnits",
      },
    ],
  };

  return sarifOutput;
}

// Find all 'content-*.json' files in the directory. dirname should include the full path
function findContent(searchDir) {
  let contentFiles = [];
  let match = /content-.*\.json/;
  var dirItems = fs.readdirSync(searchDir);
  if (dirItems) {
    for (let i = 0; i < dirItems.length; i++) {
      if (match.test(dirItems[i])) {
        contentFiles.push(`${searchDir}/${dirItems[i]}`);
      }
    }
  } else {
    core.debug("no dir content found");
  }

  core.debug(contentFiles.toString());
  return contentFiles;
}

// Load the json content of each file in a list and return them as a list
function loadContent(files) {
  let contents = [];
  if (files) {
    files.forEach((item) => contents.push(JSON.parse(fs.readFileSync(item))));
  }
  return contents;
}

// Merge the multiple content output types into a single array
function mergeResults(contentArray) {
  return contentArray.reduce((merged, n) => merged.concat(n.content), []);
}

async function downloadGrype(version) {
  let url = `https://raw.githubusercontent.com/anchore/grype/main/install.sh`;

  core.debug(`Installing ${version}`);

  // TODO: when grype starts supporting unreleased versions, support it here
  // Download the installer, and run
  const installPath = await cache.downloadTool(url);
  // Make sure the tool's executable bit is set
  await exec(`chmod +x ${installPath}`);

  let cmd = `${installPath} -b ${installPath}_grype v${version}`;
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
}

function sourceScheme() {
  // This potentially can be removed once grype starts reporting what it used to perform the scan
  // in the JSON output
  // Any newer schemes like OCI need to be added here
  if (core.getInput("image") != "") {
    return "docker";
  }
  // Only two options are currently supported
  return "dir";
}

function sourceInput() {
  var image = core.getInput("image");
  var path = core.getInput("path");

  if (image && path) {
    throw new Error("Cannot use both 'image' and 'path' as sources");
  }

  if (!(image || path)) {
    throw new Error(
      "At least one source for scanning needs to be provided. Available options are: image, and path"
    );
  }

  if (image != "") {
    return image;
  }

  return "dir:" + path;
}

async function run() {
  try {
    core.debug(new Date().toTimeString());
    // Grype accepts several input options, initially this action is supporting both `image` and `path`, so
    // a check must happen to ensure one is selected at least, and then return it
    const source = sourceInput();
    const debug = core.getInput("debug");
    const failBuild = core.getInput("fail-build");
    const acsReportEnable = core.getInput("acs-report-enable");
    const severityCutoff = core.getInput("severity-cutoff");
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
  debug = "false",
  failBuild = "true",
  acsReportEnable = "true",
  severityCutoff = "medium",
}) {
  const out = {};

  const SEVERITY_LIST = ["negligible", "low", "medium", "high", "critical"];
  let cmdArgs = [];

  if (debug.toLowerCase() === "true") {
    debug = "true";
    cmdArgs = [`-vv`, `-o`, `json`];
  } else {
    debug = "false";
    cmdArgs = [`-o`, `json`];
  }

  if (failBuild.toLowerCase() === "true") {
    failBuild = true;
  } else {
    failBuild = false;
  }

  if (acsReportEnable.toLowerCase() === "true") {
    acsReportEnable = true;
  } else {
    acsReportEnable = false;
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

  core.debug("Image: " + source);
  core.debug("Debug Output: " + debug);
  core.debug("Fail Build: " + failBuild);
  core.debug("Severity Cutoff: " + severityCutoff);
  core.debug("ACS Enable: " + acsReportEnable);

  core.debug("Creating options for GRYPE analyzer");

  // Run the grype analyzer
  let cmdOutput = "";
  let cmd = `${grypeBinary}`;
  if (severityCutoff != "") {
    cmdArgs.push("--fail-on");
    cmdArgs.push(severityCutoff.toLowerCase());
  }
  cmdArgs.push(source);
  const cmdOpts = {};
  cmdOpts.listeners = {
    stdout: (data = Buffer) => {
      cmdOutput += data.toString();
    },
  };

  cmdOpts.ignoreReturnCode = true;

  core.info("\nAnalyzing: " + source);

  const exitCode = await core.group("Grype Output", () => {
    core.info(`Executing: ${cmd} ` + cmdArgs.join(" "));
    return exec(cmd, cmdArgs, cmdOpts);
  });

  let grypeVulnerabilities = JSON.parse(cmdOutput);

  if (acsReportEnable) {
    try {
      const serifOut = sarifGrypeGeneration(
        grypeVulnerabilities,
        severityCutoff.toLowerCase(),
        grypeVersion,
        source
      );
      Object.assign(out, serifOut);
    } catch (err) {
      throw new Error(err);
    }
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

function sarifGrypeGeneration(
  grypeVulnerabilities,
  severity_cutoff_param,
  version,
  source
) {
  // sarif generate section
  const SARIF_FILE = "./results.sarif";
  let sarifOutput = vulnerabilities_to_sarif(
    grypeVulnerabilities,
    severity_cutoff_param,
    version,
    source
  );
  fs.writeFileSync(SARIF_FILE, JSON.stringify(sarifOutput, null, 2));
  return {
    sarif: SARIF_FILE,
  };
  // end sarif generate section
}

module.exports = {
  run,
  runScan,
  installGrype,
  mergeResults,
  findContent,
  loadContent,
  vulnerabilities_to_sarif,
  convert_severity_to_acs_level,
};

if (require.main === module) {
  run().catch((err) => {
    throw new Error(err);
  });
}
