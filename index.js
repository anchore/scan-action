const core = require('@actions/core');
const execSync = require('child_process').execSync;
const fs = require('fs');

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
        console.log("no dir content found");
    }

    console.log(contentFiles);
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


async function run() {
    try {
        core.debug((new Date()).toTimeString());

        const required_option = {required: true};
        const billOfMaterialsPath = "./anchore-reports/content.json";
        const image_reference = core.getInput('image-reference', required_option);
        const dockerfile_path = core.getInput('dockerfile-path');
        let debug = core.getInput('debug');
        let fail_build = core.getInput('fail-build');
        let include_packages = core.getInput('include-app-packages');
        const custom_policy_path = core.getInput('custom-policy-path');
        let inline_scan_image = "docker.io/anchore/inline-scan-slim:v0.5.1";
        const scan_scriptname = "inline_scan-v0.5.1";
        var policy_bundle_path = `${__dirname}/lib/critical_security_policy.json`;
        var policy_bundle_name = "critical_security_policy";

        if (custom_policy_path) {
            let workspace = process.env.GITHUB_WORKSPACE;
            if (!workspace) {
                workspace = ".";
            }
            let bundle_path = `${workspace}/${custom_policy_path}`;
            let bundle_name = "";
            core.debug(`Loading custom bundle from ${bundle_path}`);

            // Load the bundle to extract the policy id
            let custom_policy = fs.readFileSync(bundle_path);

            if (custom_policy) {
                core.debug('loaded custom bundle ' + custom_policy);
                custom_policy = JSON.parse(custom_policy);
                bundle_name = custom_policy.id;
                if (!bundle_name) {
                    throw new Error("Could not extract id from custom policy bundle. May be malformed json or not contain id property");
                } else {
                    core.info(`Detected custom policy id: ${bundle_name}`);
                }
                policy_bundle_name = bundle_name;
                policy_bundle_path = bundle_path;
            } else {
                throw new Error(`Custom policy specified at ${policy_bundle_path} but not found`);
            }
        }

        if (!debug) {
            debug = "false";
        } else {
            debug = "true";
        }

        if (!fail_build) {
            fail_build = "false";
        } else {
            fail_build = "true";
        }
        if (!include_packages) {
            include_packages = false;
        } else {
            include_packages = true;
            inline_scan_image = "docker.io/anchore/inline-scan:v0.5.1";
        }

        core.info('Image: ' + image_reference);
        core.info('Dockerfile path: ' + dockerfile_path);
        core.info('Inline Scan Image: ' + inline_scan_image);
        core.info('Debug Output: ' + debug);
        core.info('Fail Build: ' + fail_build);
        core.info('Include App Packages: ' + include_packages);
        core.info('Custom Policy Path: ' + custom_policy_path);

        core.debug('Policy path for evaluation: ' + policy_bundle_path);
        core.debug('Policy name for evaluation: ' + policy_bundle_name);

        let cmd = `${__dirname}/lib/run_scan ${__dirname}/lib ${scan_scriptname} ${inline_scan_image} ${image_reference} ${debug} ${policy_bundle_path} ${policy_bundle_name}`;
        if (dockerfile_path) {
            cmd = `${cmd} ${dockerfile_path}`
        }
        core.info('\nAnalyzing image: ' + image_reference);
        execSync(cmd, {stdio: 'inherit'});

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

        core.setOutput('billofmaterials', billOfMaterialsPath);
        core.setOutput('vulnerabilities', './anchore-reports/vulnerabilities.json');
        core.setOutput('policycheck', policyStatus);

        if (fail_build === "true" && policyStatus === "fail") {
            core.setFailed("Image failed Anchore policy evaluation");
        }

    } catch (error) {
        core.setFailed(error.message);
    }
}

module.exports = {run, mergeResults, findContent, loadContent};

if (require.main === module) {
    run();
}
