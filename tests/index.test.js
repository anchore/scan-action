jest.mock('@actions/core');
jest.mock('child_process');
jest.mock('fs');

const core = require('@actions/core');
const child_process = require('child_process');
const fs = require('fs');

const run = require('..');

describe('anchore-scan-action', () => {
    beforeEach(() => {
        child_process.execSync = jest.fn();
        fs.readFileSync = jest.fn(() => {
            return ""
        });
    });

    it('completes the build successfully when there are no policy violations', async () => {
        core.getInput = jest
            .fn()
            .mockReturnValueOnce('localbuild/testimage:12345')  // image-reference
            .mockReturnValueOnce('./Dockerfile')                // dockerfile-path
            .mockReturnValueOnce('true')                        // debug
            .mockReturnValueOnce('true');                       // fail_build
        core.setFailed = jest.fn();

        await run();

        expect(core.setFailed).not.toHaveBeenCalled();
    });
});
