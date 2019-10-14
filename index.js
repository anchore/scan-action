const core = require('@actions/core');
const execSync = require('child_process').execSync;
const fs = require('fs');

// most @actions toolkit packages have async methods
async function run() {
    try {
        core.debug((new Date()).toTimeString());

        let image_reference = core.getInput('image_reference');
        let dockerfile_path = core.getInput('dockerfile_path');
        let scan_scriptname = core.getInput('scan_scriptname');
        let inline_scan_image = core.getInput('inline_scan_image');
        let debug = core.getInput('debug');
        let fail_build = core.getInput('fail_build')
        let policy_bundle_path = `${__dirname}/lib/critical_security_policy.json`
        let policy_bundle_name = "critical_security_policy"

        // overrides just for testing locally
        image_reference = "docker.io/alpine:3.8"
        //image_reference = "mylocalimage:latest"
        //image_reference = "docker.io/dnurmi/testrepo:node_critical_pass"
        //dockerfile_path = "/tmp/Dockerfile"
        //scan_scriptname = "inline_scan-v0.5.0"
        //debug = "true"
        //fail_build = "true"

        if (!image_reference) {
            throw new Error("Must specify a container image to analyze using 'image_reference' input")
        }
        if (!scan_scriptname) {
            scan_scriptname = "inline_scan-v0.5.0"
        }
        if (!inline_scan_image) {
            //inline_scan_image = "docker.io/dnurmi/testrepo:inline-scan-slim-v0.5.0"
            inline_scan_image = "docker.io/dnurmi/testrepo:inline-scan-slim-v0.5.1-dev"	    
        }
        if (!debug) {
            debug = "false"
        } else {
            debug = "true"
        }
        if (!fail_build) {
            fail_build = "false"
        } else {
            fail_build = "true"
        }

        console.log('Image: ', image_reference);
        console.log('Dockerfile path: ', dockerfile_path);
        console.log('Scriptname: ', scan_scriptname);
        console.log('Inline Scan Image: ', inline_scan_image);
        console.log('Debug Output: ', debug);
        console.log('Fail Build: ', fail_build);

        let cmd = `${__dirname}/lib/run_scan ${__dirname}/lib ${scan_scriptname} ${inline_scan_image} ${image_reference} ${debug} ${policy_bundle_path} ${policy_bundle_name}`;
        if (dockerfile_path) {
            cmd = `${cmd} ${dockerfile_path}`
        }
        console.log('\nAnalyzing image: ' +image_reference)
        execSync(cmd, {stdio: 'inherit'});

        let rawdata = fs.readFileSync('./anchore-reports/policy_evaluation.json');
        let policyEval = JSON.parse(rawdata);
        let keys = Object.keys(policyEval[0]);
        let policyStatus = policyEval[0][keys[0]][Object.keys(policyEval[0][keys[0]])[0]][0].status;

        core.debug((new Date()).toTimeString());

        core.setOutput('time', new Date().toTimeString());
        core.setOutput('billofmaterials', './anchore-reports/content-os.json');
        core.setOutput('vulnerabilities', './anchore-reports/vulnerabilities.json');
        core.setOutput('policycheck', policyStatus);

        if (fail_build == "true" && policyStatus == "fail") {
            core.setFailed("Image failed Anchore policy evaluation")
        }

    } catch (error) {
        core.setFailed(error.message);
    }
}

run();
