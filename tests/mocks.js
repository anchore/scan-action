import test, { mock as nodeMock } from "node:test";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import process from "node:process";

const dateNow = Date.now;

test.beforeEach(() => {
  nodeMock.method(Date, "now", () => 1482363367071);
});

test.afterEach(() => {
  cleanup();
  nodeMock.restoreAll();
});

const originalEnv = process.env;

test.before(() => {
  process.env = {
    ...process.env,
    RUNNER_TOOL_CACHE: "/tmp/actions/cache",
    RUNNER_TEMP: "/tmp/actions/temp",
  };
});

test.after(() => {
  process.env = originalEnv;
});

const cleanups = [];

export function onCleanup(fn) {
  cleanups.push(fn);
}

export function cleanup() {
  for (let fn = cleanups.pop(); fn; fn = cleanups.pop()) {
    fn();
  }
}

export async function mock(lib, overrides) {
  // are we mocking module name or methods directly?
  if (typeof lib === "string") {
    const { _: originalDefault, ...originalNamed } = await import(lib);
    nodeMock.module(lib, {
      defaultExport: originalDefault,
      namedExports: {
        ...originalNamed,
        ...overrides,
      },
    });
  } else {
    for (const k of Object.keys(overrides)) {
      await nodeMock.method(lib, k, overrides[k]);
    }
  }
}

export async function mockIO(inputs, actionsCoreOverrides = {}) {
  const outputs = {};
  await mock("@actions/core", {
    getInput(name) {
      return inputs[name];
    },
    setOutput(name, value) {
      outputs[name] = value;
    },
    // ignore setFailed calls that set process.exitCode due to https://github.com/jestjs/jest/issues/14501
    setFailed() {},
    ...actionsCoreOverrides,
  });
  return outputs;
}

export function setEnv(env) {
  const originalValues = {};
  for (const k of Object.keys(env)) {
    if (k in process.env) {
      originalValues[k] = process.env[k];
    }
    process.env[k] = env[k];
  }
  onCleanup(() => {
    for (const k of Object.keys(env)) {
      if (k in originalValues) {
        process.env[k] = originalValues[k];
      } else {
        delete process.env[k];
      }
    }
  });
}

export function tmpdir() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "scan-action-test-"));
  onCleanup(() => {
    if (fs.existsSync(dir)) {
      fs.rmSync(dir, { recursive: true });
    }
  });
  return dir;
}

export async function run() {
  // get a new version of run with mocks replaced
  const { run } = await import(`../action.js?t=${dateNow()}`);
  await run();
}

// runCapturing mocks input params with the provided input, captures stdout,
// sets test db environment variables, and runs the action
export async function runCapturing(inputs) {
  let failure = "";
  let stdout = "";

  const append = (...args) => {
    stdout += args.join(" ") + "\n";
  };

  const outputs = await mockIO(inputs, {
    error: append,
    info: append,
    debug: append,
    warning: append,
    setFailed: (...args) => {
      append(...args);
      failure = args.join(" ");
    },
  });

  setEnv({
    GRYPE_DB_AUTO_UPDATE: "false",
    GRYPE_DB_VALIDATE_AGE: "false",
  });

  await mock(console, {
    log: append,
    error: append,
    warn: append,
    info: append,
    debug: append,
    trace: append,
  });

  await run();

  return {
    stdout,
    failure,
    outputs,
  };
}
