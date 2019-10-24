jest.mock('@actions/core');
jest.mock('child_process');
jest.mock('fs');

const core = require('@actions/core');
const execSync = require('child_process').execSync;
const fs = require('fs');

describe('anchore-scan-action', () => {
    beforeEach(() => {

    });

    it('runs tests', () => {
        expect(1 + 1).toBe(2);
    });
});
