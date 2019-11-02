jest.mock('@actions/core');
jest.mock('child_process');
jest.mock('fs');

const _ = require('lodash');
const core = require('@actions/core');
const child_process = require('child_process');
const fs = require('fs');

const run = require('..');
const policyEvaluationFixture = require('./fixtures/policy_evaluation.fixture');

describe('anchore-scan-action', () => {
    beforeEach(() => {
        child_process.execSync = jest.fn();

        core.getInput = jest
            .fn()
            .mockReturnValueOnce('localbuild/testimage:12345')  // image-reference
            .mockReturnValueOnce('./Dockerfile')                // dockerfile-path
            .mockReturnValueOnce('true')                        // debug
            .mockReturnValueOnce('true')                        // fail-build
            .mockReturnValueOnce('true')                        // include-app-packages
            .mockReturnValueOnce(null);                         // custom-policy-path
    });

    it('completes the build successfully when there are no policy violations', async () => {
        fs.readFileSync = jest.fn(() => {
            return JSON.stringify(policyEvaluationFixture);
        });
        core.setFailed = jest.fn();

        await run();

        expect(core.setFailed).not.toHaveBeenCalled();
    });

    it('fails the build when there is a policy violation', async () => {
        fs.readFileSync = jest.fn(() => {
            // Set the status to fail
            _.set(policyEvaluationFixture[0], 'sha256:0c24303.nginx:latest[0].status', 'fail');

            return JSON.stringify(policyEvaluationFixture);
        });
        core.setFailed = jest.fn();

        await run();

        expect(core.setFailed).toHaveBeenCalled();
    });
});
