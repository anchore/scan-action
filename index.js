const cache = require('@actions/tool-cache');
const core = require('@actions/core');
const { exec } = require('@actions/exec');
const fs = require('fs');

const scanScript = 'inline_scan';
const defaultAnchoreVersion = '0.7.2';

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

function render_results(vulnerabilities, severity_cutoff_param, dockerfile_path_param) {
    var ret = {}
    var dockerfile_location = dockerfile_path_param
    if (!dockerfile_location) {
        dockerfile_location = "Dockerfile"
    }
    if (vulnerabilities) {
    ret = vulnerabilities.map(v =>
                                   {
                                   return {
                                       "ruleId": "ANCHOREVULN_"+v.vuln+"_"+v.package_type+"_"+v.package,
                                       "ruleIndex": 0,
                                       "level": convert_severity_to_acs_level(v.severity, severity_cutoff_param),
                                       "message": {
                                       "text": "This dockerfile results in a container image that has installed software with a vulnerability: ("+v.package+" type="+v.package_type+")",
                                       "id": "default"
                                       },
                                       "analysisTarget": {
                                       "uri": dockerfile_location,
                                       "index": 0
                                       },
                                       "locations": [
                                       {
                                           "physicalLocation": {
                                           "artifactLocation": {
                                               "uri": dockerfile_location
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

function vulnerabilities_to_sarif(input_vulnerabilities, severity_cutoff_param, anchore_version, dockerfile_path_param) {
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
            "version": anchore_version,
            "semanticVersion": anchore_version,
            "dottedQuadFileVersion": anchore_version + ".0",
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
        "results": render_results(vulnerabilities, severity_cutoff_param, dockerfile_path_param), 
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

async function run() {
    try {
        core.debug((new Date()).toTimeString());

        const requiredOption = {required: true};
        const imageReference = core.getInput('image-reference', requiredOption);
        //const imageReference = "alpine:latest"
        const customPolicyPath = core.getInput('custom-policy-path');
        const dockerfilePath = core.getInput('dockerfile-path');
        var debug = core.getInput('debug');
        //var debug = "debug"
        var failBuild = core.getInput('fail-build');
        var acsReportEnable = core.getInput('acs-report-enable');
        var acsSevCutoff = core.getInput('acs-report-severity-cutoff');
        var includePackages = core.getInput('include-app-packages');
        var version = core.getInput('anchore-version');
        const billOfMaterialsPath = "./anchore-reports/content.json";
        const runScan = `${__dirname}/lib/run_scan.sh`;
        var policyBundlePath = `${__dirname}/lib/critical_security_policy.json`;
        var policyBundleName = "critical_security_policy";
        var inlineScanImage;
        const SEVERITY_LIST = ['Unknown', 'Negligible', 'Low', 'Medium', 'High', 'Critical'];

        if (!debug) {
            debug = "false";
        } else {
            debug = "true";
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

        if (!acsSevCutoff) {
            acsSevCutoff = "Medium"
        }
        else if (
            !SEVERITY_LIST.some(
              item =>
                typeof acsSevCutoff === 'string' &&
                item === acsSevCutoff,
            )
          ) {
            throw new Error ('Invalid acs-report-severity-cutoff value is set - please ensure you are choosing either Unknown, Negligible, Low, Medium, High, or Critical');
          }

        if (!version) {
            version = `${defaultAnchoreVersion}`;
        }

        if (!includePackages) {
            includePackages = false;
            inlineScanImage = `docker.io/anchore/inline-scan-slim:v${version}`;
        } else {
            includePackages = true;
            inlineScanImage = `docker.io/anchore/inline-scan:v${version}`;
        }

        if (customPolicyPath) {
            let workspace = process.env.GITHUB_WORKSPACE;
            if (!workspace) {
                workspace = ".";
            }
            let bundlePath = `${workspace}/${customPolicyPath}`;
            let bundleName = "";
            core.debug(`Loading custom bundle from ${bundlePath}`);

            // Load the bundle to extract the policy id
            let customPolicy = fs.readFileSync(bundlePath);

            if (customPolicy) {
                core.debug('loaded custom bundle ' + customPolicy);
                customPolicy = JSON.parse(customPolicy);
                bundleName = customPolicy.id;
                if (!bundleName) {
                    throw new Error("Could not extract id from custom policy bundle. May be malformed json or not contain id property");
                } else {
                    core.info(`Detected custom policy id: ${bundleName}`);
                }
                policyBundleName = bundleName;
                policyBundlePath = bundlePath;
            } else {
                throw new Error(`Custom policy specified at ${policyBundlePath} but not found`);
            }
        }

        await installInlineScan(version);

        core.debug('Image: ' + imageReference);
        core.debug('Dockerfile path: ' + dockerfilePath);
        core.debug('Inline Scan Image: ' + inlineScanImage);
        core.debug('Debug Output: ' + debug);
        core.debug('Fail Build: ' + failBuild);
        core.debug('Include App Packages: ' + includePackages);
        core.debug('Custom Policy Path: ' + customPolicyPath);
        core.debug('ACS Enable: ' + acsReportEnable);	
        core.debug('ACS Severity Cutoff: ' + acsSevCutoff);	

        core.debug('Policy path for evaluation: ' + policyBundlePath);
        core.debug('Policy name for evaluation: ' + policyBundleName);

        let cmd = `${runScan} ${scanScript} ${inlineScanImage} ${imageReference} ${debug} ${policyBundlePath} ${policyBundleName}`;
        if (dockerfilePath) {
            cmd = `${cmd} ${dockerfilePath}`
        }
        core.info('\nAnalyzing image: ' + imageReference);
        await exec(cmd);

        let rawdata = fs.readFileSync('./anchore-reports/policy_evaluation.json');
        let policyEval = JSON.parse(rawdata);
        let imageId = Object.keys(policyEval[0]);
        let imageTag = Object.keys(policyEval[0][imageId[0]]);
        let policyStatus = policyEval[0][imageId[0]][imageTag][0]['status'];

        try {
            let billOfMaterials = {
                "packages": mergeResults(loadContent(findContent("./anchore-reports/")))
            };
            fs.writeFileSync(billOfMaterialsPath, JSON.stringify(billOfMaterials));
        } catch (error) {
            core.error("Error constructing bill of materials from anchore output: " + error);
            throw error;
        }

        if (acsReportEnable) {
            try {sarifGeneration(version, acsSevCutoff, dockerfilePath);}
            catch (err) {throw new Error(err)}
        }

        core.setOutput('billofmaterials', billOfMaterialsPath);
        core.setOutput('vulnerabilities', './anchore-reports/vulnerabilities.json');
        core.setOutput('policycheck', policyStatus);
        
        if (failBuild === true && policyStatus === "fail") {
            core.setFailed("Image failed Anchore policy evaluation");
        }

    } catch (error) {
        core.setFailed(error.message);
    }
}

function sarifGeneration(anchore_version, severity_cutoff_param, dockerfile_path_param){
    // sarif generate section
    let sarifOutput = vulnerabilities_to_sarif("./anchore-reports/vulnerabilities.json", severity_cutoff_param, anchore_version, dockerfile_path_param);
    fs.writeFileSync("./results.sarif", JSON.stringify(sarifOutput, null, 2));
    // end sarif generate section
}

module.exports = {run, mergeResults, findContent, loadContent, vulnerabilities_to_sarif, convert_severity_to_acs_level};

if (require.main === module) {
    run().catch((err)=>{throw new Error(err)});
}
