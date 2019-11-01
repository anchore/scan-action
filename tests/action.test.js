const cp = require('child_process');
const path = require('path');
const process = require('process')

// shows how the runner will run a javascript action with env / stdout protocol
test('test runs', () => {
    process.env['INPUT_DEBUG'] = 'true';
    process.env['INPUT_IMAGE-REFERENCE'] = 'docker.io/alpine:latest';
    const ip = path.join(__dirname, '../index.js');
    console.log(cp.execSync(`node ${ip}`, {env: process.env}).toString());
});