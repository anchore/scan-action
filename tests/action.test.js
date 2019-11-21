const child_process = require('child_process');
const path = require('path');
const process = require('process');

// shows how the runner will run a javascript action with env / stdout protocol
test('test runs', () => {
    process.env['INPUT_DEBUG'] = 'true';
    process.env['INPUT_IMAGE-REFERENCE'] = 'docker.io/alpine:latest';
    process.env['RUNNER_TOOL_CACHE'] = '/tmp/actions/cache';
    process.env['RUNNER_TEMP'] = '/tmp/actions/temp';
    const index_path = path.join(__dirname, '../index.js');
    console.log(child_process.execSync(`node ${index_path}`, {env: process.env}).toString());
});