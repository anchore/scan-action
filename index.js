const cache = require('@actions/tool-cache');
const core = require('@actions/core');
const { exec } = require('@actions/exec');
const fs = require('fs');
const { stderr } = require('process');

//const scanScript = 'inline_scan';
const defaultAnchoreVersion = '0.8.0';

const grypeBinary = 'grype'
const grypeVersion = '0.1.0-beta.6'

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


function grype_render_rules(vulnerabilities) {
    var ret = {}
    if (vulnerabilities) {
    ret = vulnerabilities.map(v =>
                  {
                      return {
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
                  }
                 );
    }
    return(ret);
}

function grype_render_results(vulnerabilities, severity_cutoff_param, dockerfile_path_param) {
    var ret = {}
    var dockerfile_location = dockerfile_path_param
    if (!dockerfile_location) {
        dockerfile_location = "Dockerfile"
    }
    if (vulnerabilities) {
    ret = vulnerabilities.map(v =>
                                   {
                                   return {
                                       "ruleId": "ANCHOREVULN_"+v.vulnerability.id+"_"+v.artifact.type+"_"+v.artifact.name+"_"+v.artifact.version,
                                       "ruleIndex": 0,
                                       "level": convert_severity_to_acs_level(v.vulnerability.severity, severity_cutoff_param),
                                       "message": {
                                       "text": "This dockerfile results in a container image that has installed software with a vulnerability: (name="+v.artifact.name+" version="+v.artifact.version+" type="+v.artifact.type+")",
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


function grype_vulnerabilities_to_sarif(input_vulnerabilities, severity_cutoff_param, version, dockerfile_path_param) {
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
            "dottedQuadFileVersion": version + ".0",
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
        "results": grype_render_results(vulnerabilities, severity_cutoff_param, dockerfile_path_param), 
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
    const installPath = await cache.downloadTool(`https://raw.githubusercontent.com/anchore/grype/main/install.sh`);
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

async function run() {
    try {
        core.debug((new Date()).toTimeString());

        const requiredOption = {required: true};
        const imageReference = core.getInput('image-reference', requiredOption);
        //const imageReference = "alpine:3.7"
	    const dockerfilePath = core.getInput('dockerfile-path');
        var debug = core.getInput('debug');
        //var debug = 'false';
        var failBuild = core.getInput('fail-build');
        var acsReportEnable = core.getInput('acs-report-enable');
	    //var acsReportEnable = "true";
	    var severityCutoff = core.getInput('severity-cutoff');
	    //var severityCutoff = "Medium"
        var version = core.getInput('anchore-version');
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
            version = `${defaultAnchoreVersion}`;
        }

        //await installInlineScan(version);
        core.debug(`Installing grype version ${version}`);
	    await installGrype(grypeVersion);
	
        core.debug('Image: ' + imageReference);
        core.debug('Debug Output: ' + debug);
        core.debug('Fail Build: ' + failBuild);
        core.debug('Severity Cutoff: ' + severityCutoff);		
        core.debug('ACS Enable: ' + acsReportEnable);	

        // Run the grype analyzer
        let cmdOutput = '';
        let stdErr = '';
        let cmd = `${grypeBinary}`;
        let cmdArgs = [`-vv`, `-o`, `json`, `${imageReference}`];
        const cmdOpts = {};
        cmdOpts.listeners = {
                stdout: (data=Buffer) => {
                    cmdOutput += data.toString();
                },
                stderr: (data=Buffer) => {
                    stdErr += data.toString();
                }
        };

        // XXX make this optional
        core.info(stdErr)
        //cmdOpts.silent = true;
        //cmdOpts.cwd = './something';

        core.info('\nAnalyzing: ' + imageReference);
    	await exec(cmd, cmdArgs, cmdOpts);
	    let grypeVulnerabilities = JSON.parse(cmdOutput);

        // handle output
        fs.writeFileSync('./vulnerabilities.json', JSON.stringify(grypeVulnerabilities));

        if (acsReportEnable) {
            try {sarifGrypeGeneration(version, severityCutoff, dockerfilePath);}
            catch (err) {throw new Error(err)}
        }	
	
        /*
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
	*/
    } catch (error) {
        core.setFailed(error.message);
    }
}

/*
function sarifGeneration(anchore_version, severity_cutoff_param, dockerfile_path_param){
    // sarif generate section
    let sarifOutput = vulnerabilities_to_sarif("./anchore-reports/vulnerabilities.json", severity_cutoff_param, anchore_version, dockerfile_path_param);
    fs.writeFileSync("./results.sarif", JSON.stringify(sarifOutput, null, 2));
    // end sarif generate section
}
*/
function sarifGrypeGeneration(version, severity_cutoff_param, dockerfile_path_param){
    // sarif generate section
    let sarifOutput = grype_vulnerabilities_to_sarif("./vulnerabilities.json", severity_cutoff_param, version, dockerfile_path_param);
    fs.writeFileSync("./results.sarif", JSON.stringify(sarifOutput, null, 2));
    // end sarif generate section
}

module.exports = {run, mergeResults, findContent, loadContent, vulnerabilities_to_sarif, convert_severity_to_acs_level};

if (require.main === module) {
    run().catch((err)=>{throw new Error(err)});
}
