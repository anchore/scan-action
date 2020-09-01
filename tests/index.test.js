const error = require('../dist');
jest.mock('@actions/core');
jest.mock('@actions/exec');
jest.mock('@actions/tool-cache');

const _ = require('lodash');
const core = require('@actions/core');
const exec = require('@actions/exec');
const path = require('path');
const fs = require('fs');

const main = require('..');
const policyEvaluationFixture = require('./fixtures/policy_evaluation.fixture');
const contentMergeFixture = require('./fixtures/content-merge.fixture');

describe('unit-tests', () => {
    it('tests merge of outputs into single bill of materials with os-only packages', () => {
        let merged = main.mergeResults([contentMergeFixture["content-os.json"]]);
        //console.log("os-only output: " +JSON.stringify(merged));
        expect(merged.length).toBeGreaterThan(0);

    });

    it('tests merge of outputs into single bill of materials with all packages', () => {
        let merged = main.mergeResults([contentMergeFixture["content-os.json"], contentMergeFixture["content-npm.json"], contentMergeFixture["content-gem.json"], contentMergeFixture["content-java.json"], contentMergeFixture["content-python.json"]]);
        //console.log("merged output: " +JSON.stringify(merged));
        expect(merged.length).toBeGreaterThan(0);
    });

    it('tests finding content files in dir', () => {
        let testPath = path.join(__dirname, "fixtures");

        const mock = jest.spyOn(fs, 'readdirSync');
        mock.mockImplementation(() => {
            return Object.keys(contentMergeFixture);
        });

        let contentFiles = main.findContent(testPath);
        expect(contentFiles.length).toEqual(5);

        mock.mockRestore();  // restore fs.readdirSync()
    });

    it('tests loading content in list', () => {
        const mock = jest.spyOn(fs, 'readFileSync');
        mock.mockImplementation((i) => {
            return JSON.stringify(contentMergeFixture[i]);
        });

        let contentFiles = main.loadContent(Object.keys(contentMergeFixture));
        expect(contentFiles.length).toEqual(5);

        mock.mockRestore();  // restore fs.readFileSync()
    });
});

describe('functional-tests', () => {
    beforeEach(() => {
        exec.exec = jest.fn();

        const mockReaddirSync = jest.spyOn(fs, 'readdirSync');
        mockReaddirSync.mockImplementation(() => {
            return Object.keys(contentMergeFixture);
        });

        const mockWriteFileSync = jest.spyOn(fs, 'writeFileSync');
        mockWriteFileSync.mockImplementation((i) => jest.fn());

        core.getInput = jest
            .fn()
            .mockReturnValueOnce('localbuild/testimage:12345')  // image-reference
            .mockReturnValueOnce('./Dockerfile')                // dockerfile-path
            .mockReturnValueOnce('true')                        // debug
            .mockReturnValueOnce('true')                        // fail-build
            .mockReturnValueOnce('false')                       // acs-report
            .mockReturnValueOnce('Medium')                      // sev-cut-off
            .mockReturnValueOnce(null)                          // version	
    });

});
