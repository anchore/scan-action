const cache = require('@actions/tool-cache');
const core = require('@actions/core');
const { exec } = require('@actions/exec');
const fs = require('fs');

const grypeBinary = 'grype'
const grypeVersion = '0.1.0-beta.7'

// sarif code
function convert_severity_to_acs_level(input_severity, severity_cutoff_param) {
    var ret = "error"
    const severityLevels = {
    'Unknown': 0,
    'Negligible': 1,
    'Low': 2,
    'Medium': 3,
    'High': 4,
    'Critical': 5
    }

    if (severityLevels[input_severity] < severityLevels[severity_cutoff_param]) {
    ret = "warning"
    }

    return(ret)
}

function render_rules(vulnerabilities) {
    var ret = {}
    if (vulnerabilities) {
    ret = vulnerabilities.map(v =>
                  {
                      return {
                      "id": "ANCHOREVULN_"+v.vuln+"_"+v.package_type+"_"+v.package,
                      "shortDescription": {
                          "text": v.vuln + " Severity=" + v.severity + " Package=" + v.package
                      },
                      "fullDescription": {
                          "text": v.vuln + " Severity=" + v.severity + " Package=" + v.package
                      },
                      "help": {
                          "text": "Vulnerability "+v.vuln+"\n"+
                          "Severity: "+v.severity+"\n"+
                          "Package: "+v.package_name+"\n"+
                          "Version: "+v.package_version+"\n"+
                          "Fix Version: "+v.fix+"\n"+
                          "Type: "+v.package_type+"\n"+
                          "Location: "+v.package_path+"\n"+
                          "Data Namespace: "+v.feed + ", "+v.feed_group+"\n"+
                          "Link: ["+v.vuln+"]("+v.url+")",
                          "markdown": "**Vulnerability "+v.vuln+"**\n"+
                          "| Severity | Package | Version | Fix Version | Type | Location | Data Namespace | Link |\n"+
                          "| --- | --- | --- | --- | --- | --- | --- | --- |\n"+
                          "|"+v.severity+"|"+v.package_name+"|"+v.package_version+"|"+v.fix+"|"+v.package_type+"|"+v.package_path+"|"+v.feed_group+"|["+v.vuln+"]("+v.url+")|\n"
                      }

                      }
                  }
                 );
    }
    return(ret);
}

function getLocation(v) {
    dockerfilePath = core.getInput('dockerfile-path');
    if (dockerfilePath != "") {
        return dockerfilePath;
    }
    if (v.artifact.locations.length) {
        return v.artifact.locations[0];
    }
    // XXX there is room for improvement here, trying to mimick previous behavior
    // If no `dockerfile-path` was provided, and in the improbable situation where there
    // are no locations for the artifact, return 'Dockerfile'
    return "Dockerfile"
}

function textMessage(v) {
    scheme = sourceScheme();
    if (["dir", "tar"].includes(scheme)) {
        prefix = "The path " + getLocation(v) + " would result in an installed vulnerability: "
    } else {
        prefix = "The container image contains software with a vulnerability: "
    }
    return prefix + "("+v.package+" type="+v.package_type+")"
}


function dottedQuadFileVersion(version) {
    // The dotted quad version requirements of the SARIF schema has some strict requirements. Because
    // it is tied to the version which can be (optionally) set by the user, it isn't enough to blindly
    // add a trailing ".0" - This function validates the end result, falling back to a version that would
    // pass the schema while issuing a warning.
    const pattern = /[0-9]+(\.[0-9]+){3}/
    // grype has some releases with dashes, ensure these are pruned
    version = version.split('-')[0];
    
    // None of the Grype versions will ever have version with four parts, add a trailing `.0` here
    version = version + ".0";

    if (!version.match(pattern)) {
        // After prunning and adding a trailing .0 we still got a failure. Warn about this, and fallback to
        // a made-up version guaranteed to work.
        core.warning(
            `Unable to produce an acceptable four-part dotted version: ${version} \n` +
            `SARIF reporting requires pattern matching against "[0-9]+(\.[0-9]+){3}" \n` +
            "Will fallback to 0.0.0.0" 
        );
        return "0.0.0.0";
    }
    return version;
}


function render_results(vulnerabilities, severity_cutoff_param) {
    var ret = {}

    if (vulnerabilities) {
    ret = vulnerabilities.map(v =>
                                   {
                                   return {
                                       "ruleId": "ANCHOREVULN_"+v.vuln+"_"+v.package_type+"_"+v.package,
                                       "ruleIndex": 0,
                                       "level": convert_severity_to_acs_level(v.severity, severity_cutoff_param),
                                       "message": {
                                       "text": textMessage(v),
                                       "id": "default"
                                       },
                                       "analysisTarget": {
                                       "uri": getLocation(v),
                                       "index": 0
                                       },
                                       "locations": [
                                       {
                                           "physicalLocation": {
                                           "artifactLocation": {
                                               "uri": getLocation(v)
                                           },
                                           "region": {
                                               "startLine": 1,
                                               "startColumn": 1,
                                               "endLine": 1,
                                               "endColumn": 1,
                                               "byteOffset": 1,
                                               "byteLength": 1
                                           }
                                           },
                                           "logicalLocations": [
                                           {
                                               "fullyQualifiedName": "dockerfile"
                                           }
                                           ]
                                       }
                                       ],
                                       "suppressions": [
                                       {
                                           "kind": "external"
                                       }
                                       ],
                                       "baselineState": "unchanged"
                                   }
                                   }
                                  )
    }
    return(ret);
}


function vulnerabilities_to_sarif(input_vulnerabilities, severity_cutoff_param, version) {
    let rawdata = fs.readFileSync(input_vulnerabilities);
    let vulnerabilities_raw = JSON.parse(rawdata);
    let vulnerabilities = vulnerabilities_raw.vulnerabilities;

    const sarifOutput = {
    "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.4.json",
    "version": "2.1.0",
    "runs": [
            {
        "tool": {
            "driver": {
            "name": "Anchore Container Vulnerability Report",
            "fullName": "Anchore Container Vulnerability Report",
            "version": version,
            "semanticVersion": version,
            "dottedQuadFileVersion": dottedQuadFileVersion(version),
            "rules": render_rules(vulnerabilities)
            }
        },
        "logicalLocations": [
                    {
            "name": "dockerfile",
            "fullyQualifiedName": "dockerfile",
            "kind": "namespace"
                    }
        ],
        "results": render_results(vulnerabilities, severity_cutoff_param),
        "columnKind": "utf16CodeUnits"
            }
    ]
    }

    return(sarifOutput)
}


function grype_render_rules(vulnerabilities) {
    var ret = {}
    if (vulnerabilities) {
    let vulnIDs = [];
    // This uses .reduce() because there can be duplicate vulnerabilities which the SARIF schema complains about.
    ret = vulnerabilities.reduce(function(result, v) {
        if (!vulnIDs.includes(v.vulnerability.id)) {
          vulnIDs.push(v.vulnerability.id);
          result.push(
            {
                "id": "ANCHOREVULN_"+v.vulnerability.id+"_"+v.artifact.type+"_"+v.artifact.name+"_"+v.artifact.version,
                "shortDescription": {
                    "text": v.vulnerability.id + " Severity=" + v.vulnerability.severity + " Package=" + v.artifact.name + " Version=" + v.artifact.version
                },
                "fullDescription": {
                    "text": v.vulnerability.id + " Severity=" + v.vulnerability.severity + " Package=" + v.artifact.name + " Version=" + v.artifact.version
                },
                "help": {
                    "text": "Vulnerability "+v.vulnerability.id+"\n"+
                    "Severity: "+v.vulnerability.severity+"\n"+
                    "Package: "+v.artifact.name+"\n"+
                    "Version: "+v.artifact.version+"\n"+
                    "Fix Version: "+"unknown"+"\n"+
                    "Type: "+v.artifact.type+"\n"+
                    "Location: "+v.artifact.locations[0].path+"\n"+
                    //"Data Namespace: "+v.vulnerability.matched_by.matcher +"\n"+
                    "Data Namespace: "+ "unknown" + "\n"+
                    "Link: ["+v.vulnerability.id+"]("+v.vulnerability.links[0]+")",
                    "markdown": "**Vulnerability "+v.vulnerability.id+"**\n"+
                    "| Severity | Package | Version | Fix Version | Type | Location | Data Namespace | Link |\n"+
                    "| --- | --- | --- | --- | --- | --- | --- | --- |\n"+
                    "|"+v.vulnerability.severity+"|"+v.artifact.name+"|"+v.artifact.version+"|"+"unknown"+"|"+v.artifact.type+"|"+v.artifact.locations[0].path+"|"+"unknown"+"|["+v.vulnerability.id+"]("+v.vulnerability.links[0]+")|\n"
                }
              }
          );
          
        }
        return result;
      }, []);
    }
    return(ret);
}

function grype_render_results(vulnerabilities, severity_cutoff_param) {
    var ret = {}
    if (vulnerabilities) {
    

    ret = vulnerabilities.map(v =>
                                   {  
                                   return {
                                       "ruleId": "ANCHOREVULN_"+v.vulnerability.id+"_"+v.artifact.type+"_"+v.artifact.name+"_"+v.artifact.version,
                                       "ruleIndex": 0,
                                       "level": convert_severity_to_acs_level(v.vulnerability.severity, severity_cutoff_param),
                                       "message": {
                                       "text": textMessage(v),
                                       "id": "default"
                                       },
                                       "analysisTarget": {
                                       "uri": getLocation(v),
                                       // XXX This is possibly a bug. The SARIF schema invalidates this when the index is present because there
                                       // aren't any other elements present. 
                                       //"index": 0
                                       },
                                       "locations": [
                                       {
                                           "physicalLocation": {
                                           "artifactLocation": {
                                               "uri": getLocation(v)
                                           },
                                           "region": {
                                               "startLine": 1,
                                               "startColumn": 1,
                                               "endLine": 1,
                                               "endColumn": 1,
                                               "byteOffset": 1,
                                               "byteLength": 1
                                           }
                                           },
                                           "logicalLocations": [
                                           {
                                               "fullyQualifiedName": "dockerfile"
                                           }
                                           ]
                                       }
                                       ],
                                       "suppressions": [
                                       {
                                           "kind": "external"
                                       }
                                       ],
                                       "baselineState": "unchanged"
                                   }
                                }
                            )
    }
    return(ret);
}


function grype_vulnerabilities_to_sarif(input_vulnerabilities, severity_cutoff_param, version) {
    let rawdata = fs.readFileSync(input_vulnerabilities);
    let vulnerabilities = JSON.parse(rawdata);
    //let vulnerabilities = vulnerabilities_raw.vulnerabilities;

    const sarifOutput = {
    "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.4.json",
    "version": "2.1.0",
    "runs": [
            {
        "tool": {
            "driver": {
            "name": "Anchore Container Vulnerability Report (T0)",
            "fullName": "Anchore Container Vulnerability Report (T0)",
            "version": version,
            "semanticVersion": version,
            "dottedQuadFileVersion": dottedQuadFileVersion(version),
            "rules": grype_render_rules(vulnerabilities)
            }
        },
        "logicalLocations": [
                    {
            "name": "dockerfile",
            "fullyQualifiedName": "dockerfile",
            "kind": "namespace"
                    }
        ],
        "results": grype_render_results(vulnerabilities, severity_cutoff_param),
        "columnKind": "utf16CodeUnits"
            }
    ]
    }

    return(sarifOutput)
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
        files.forEach(item => contents.push(JSON.parse(fs.readFileSync(item))));
    }
    return contents
}

// Merge the multiple content output types into a single array
function mergeResults(contentArray) {
    return contentArray.reduce((merged, n) => merged.concat(n.content), []);
}

/*
async function downloadInlineScan(version) {
    core.debug(`Installing ${version}`);
    const downloadPath = await cache.downloadTool(`https://ci-tools.anchore.io/inline_scan-v${version}`);
    // Make sure the tool's executable bit is set
    await exec(`chmod +x ${downloadPath}`);

    // Cache the downloaded file
    return cache.cacheFile(downloadPath, scanScript, scanScript, version);
  }

async function installInlineScan(version) {
    let scanScriptPath = cache.find(scanScript, version);
    if (!scanScriptPath) {
        // Not found, install it
        scanScriptPath = await downloadInlineScan(version);
    }

    // Add tool to path for this and future actions to use
    core.addPath(scanScriptPath);
}
*/

async function downloadGrype(version) {
    core.debug(`Installing ${version}`);

    // Download the installer, and run
    
    const installPath = await cache.downloadTool(`https://raw.githubusercontent.com/anchore/grype/v${grypeVersion}/install.sh`);
    // Make sure the tool's executable bit is set
    await exec(`chmod +x ${installPath}`);

    let cmd = `${installPath} -b ${installPath}_grype`
    await exec(cmd);
    let grypePath = `${installPath}_grype/grype`

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
    // Any newer schemes like OCI need to be added here
    schemes = ["dir", "tar", "docker"]
    image = core.getInput('image-reference');
    source = core.getInput('source');

    if (source != "") {
        inputValue = source;
    } else {
        inputValue = image;
    }
    
    parts = inputValue.split(":");
    // return the scheme if found
    if (schemes.includes(parts[0])) {
        return parts[0];
    }
    // A repo:tag probably, so use docker
    return "docker";

}
function sourceInput() {
    image = core.getInput('image-reference');
    source = core.getInput('source');

    // If both are defined, prefer `source`
    if (image != "" && source != "") {
        // XXX Add an extra warning about making it an error condition?
        core.warning("Both 'image-reference' and 'source' were specified, 'source' is preferred and will be used");
        return source;
    }
    // If `source` is defined then prioritize it
    if (source != "") {
        return source;
    }
    // Finally, just use the image coming from the deprecated `image-reference`
    core.warning("Please use 'source' instead of 'image-reference'")
    return image;
}


async function run() {
    try {
        core.debug((new Date()).toTimeString());

        const requiredOption = {required: true};
        // XXX backwards compatibility: image-reference was required, but grype accepts other source
        // types like a directory or a tar. This block will now support both `image-reference` and `source`
        // with a preference for `source` in the case both are supplied
        //const imageReference = core.getInput('image-reference', requiredOption);
        const source = sourceInput();
        
        var debug = core.getInput('debug');
        var failBuild = core.getInput('fail-build');
        var acsReportEnable = core.getInput('acs-report-enable');
        var severityCutoff = core.getInput('severity-cutoff');
        var version = core.getInput('grype-version');
        const billOfMaterialsPath = "./anchore-reports/content.json";
        const SEVERITY_LIST = ['Unknown', 'Negligible', 'Low', 'Medium', 'High', 'Critical'];
        console.log(billOfMaterialsPath);
        if (debug.toLowerCase() === "true") {
            debug = "true";
        } else {
            debug = "false";
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
              item =>
                typeof severityCutoff === 'string' &&
                item === severityCutoff,
            )
          ) {
            throw new Error (`Invalid severity-cutoff value is set ${debug} ${severityCutoff} - please ensure you are choosing either Unknown, Negligible, Low, Medium, High, or Critical`);
        }

        if (!version) {
            version = `${grypeVersion}`;
        }

        core.debug(`Installing grype version ${version}`);
        await installGrype(grypeVersion);

        core.debug('Image: ' + source);
        core.debug('Debug Output: ' + debug);
        core.debug('Fail Build: ' + failBuild);
        core.debug('Severity Cutoff: ' + severityCutoff);
        core.debug('ACS Enable: ' + acsReportEnable);

        core.debug('Creating options for GRYPE analyzer');

        // Run the grype analyzer
        let cmdOutput = '';
        let stdErr = '';
        let cmd = `${grypeBinary}`;
        let cmdArgs = [`-vv`, `-o`, `json`, `${source}`];
        const cmdOpts = {};
        cmdOpts.listeners = {
                stdout: (data=Buffer) => {
                    cmdOutput += data.toString();
                },
                stderr: (data=Buffer) => {
                    stdErr += data.toString();
                }
        };


        core.info('\nAnalyzing: ' + source);
        await exec(cmd, cmdArgs, cmdOpts);
        
        core.info('\nCaptured stderr from grype:\n' + stdErr);
        let grypeVulnerabilities = JSON.parse(cmdOutput);

        // handle output
        fs.writeFileSync('./vulnerabilities.json', JSON.stringify(grypeVulnerabilities));

        if (acsReportEnable) {
            try {sarifGrypeGeneration(severityCutoff, version);}
            catch (err) {throw new Error(err)}
        }


    } catch (error) {
        core.setFailed(error.message);
    }
}

function sarifGrypeGeneration(severity_cutoff_param, version){
    // sarif generate section
    let sarifOutput = grype_vulnerabilities_to_sarif("./vulnerabilities.json", severity_cutoff_param, version);
    fs.writeFileSync("./results.sarif", JSON.stringify(sarifOutput, null, 2));
    // end sarif generate section
}

module.exports = {run, mergeResults, findContent, loadContent, vulnerabilities_to_sarif, convert_severity_to_acs_level};

if (require.main === module) {
    run().catch((err)=>{throw new Error(err)});
}
