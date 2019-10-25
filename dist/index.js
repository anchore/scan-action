module.exports =
/******/ (function(modules, runtime) { // webpackBootstrap
/******/ 	"use strict";
/******/ 	// The module cache
/******/ 	var installedModules = {};
/******/
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/
/******/ 		// Check if module is in cache
/******/ 		if(installedModules[moduleId]) {
/******/ 			return installedModules[moduleId].exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = installedModules[moduleId] = {
/******/ 			i: moduleId,
/******/ 			l: false,
/******/ 			exports: {}
/******/ 		};
/******/
/******/ 		// Execute the module function
/******/ 		modules[moduleId].call(module.exports, module, module.exports, __webpack_require__);
/******/
/******/ 		// Flag the module as loaded
/******/ 		module.l = true;
/******/
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/
/******/
/******/ 	__webpack_require__.ab = __dirname + "/";
/******/
/******/ 	// the startup function
/******/ 	function startup() {
/******/ 		// Load entry module and return exports
/******/ 		return __webpack_require__(410);
/******/ 	};
/******/
/******/ 	// run startup
/******/ 	return startup();
/******/ })
/************************************************************************/
/******/ ({

/***/ 129:
/***/ (function(module) {

module.exports = require("child_process");

/***/ }),

/***/ 410:
/***/ (function(module, __unusedexports, __webpack_require__) {

const core = __webpack_require__(739);
const execSync = __webpack_require__(129).execSync;
const fs = __webpack_require__(747);

async function run() {
    try {
        core.debug((new Date()).toTimeString());

        const image_reference = core.getInput('image-reference');
        const dockerfile_path = core.getInput('dockerfile-path');
        let debug = core.getInput('debug');
        let fail_build = core.getInput('fail-build')
        const policy_bundle_path = __webpack_require__.ab + "critical_security_policy.json"
        const policy_bundle_name = "critical_security_policy"

        const scan_scriptname = "inline_scan-v0.5.1"
        const inline_scan_image = "docker.io/anchore/inline-scan-slim:v0.5.1"

        if (!image_reference) {
            throw new Error("Must specify a container image to analyze using 'image_reference' input")
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

        core.info('Image: ' +image_reference);
        core.info('Dockerfile path: ' +dockerfile_path);
        core.info('Inline Scan Image: ' +inline_scan_image);
        core.info('Debug Output: ' +debug);
        core.info('Fail Build: ' +fail_build);

        let cmd = `${__dirname}/lib/run_scan ${__dirname}/lib ${scan_scriptname} ${inline_scan_image} ${image_reference} ${debug} ${policy_bundle_path} ${policy_bundle_name}`;
        if (dockerfile_path) {
            cmd = `${cmd} ${dockerfile_path}`
        }
        core.info('\nAnalyzing image: ' +image_reference)
        execSync(cmd, {stdio: 'inherit'});

        let rawdata = fs.readFileSync('./anchore-reports/policy_evaluation.json');
        let policyEval = JSON.parse(rawdata);
        let imageId = Object.keys(policyEval[0]);
        let imageTag = Object.keys(policyEval[0][imageId[0]]);
        let policyStatus = policyEval[0][imageId[0]][imageTag][0]['status']

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

module.exports = run;

if (require.main === require.cache[eval('__filename')]) {
    run();
}


/***/ }),

/***/ 739:
/***/ (function() {

eval("require")("@actions/core");


/***/ }),

/***/ 747:
/***/ (function(module) {

module.exports = require("fs");

/***/ })

/******/ });