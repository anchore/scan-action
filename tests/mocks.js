const core = require("@actions/core");
const fs = require("fs");
const path = require("path");
const os = require("os");
const process = require("process");

const cleanups = [];

module.exports = {
  onCleanup(fn) {
    cleanups.push(fn);
  },

  cleanup() {
    for (let fn = cleanups.pop(); fn; fn = cleanups.pop()) {
      fn();
    }
    jest.restoreAllMocks();
  },

  mock(lib, overrides) {
    for (const name of Object.keys(overrides)) {
      module.exports.onCleanup(
        jest.spyOn(lib, name).mockImplementation(overrides[name]).mockRestore,
      );
    }
  },

  mockIO(inputs) {
    const outputs = {};
    module.exports.mock(core, {
      getInput(name) {
        return inputs[name];
      },
      setOutput(name, value) {
        outputs[name] = value;
      },
    });
    return outputs;
  },

  setEnv(env) {
    const originalValues = {};
    for (const k of Object.keys(env)) {
      if (k in process.env) {
        originalValues[k] = process.env[k];
      }
      process.env[k] = env[k];
    }
    module.exports.onCleanup(() => {
      for (const k of Object.keys(env)) {
        if (k in originalValues) {
          process.env[k] = originalValues[k];
        } else {
          delete process.env[k];
        }
      }
    });
  },

  tmpdir() {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "scan-action-test-"));
    module.exports.onCleanup(() => {
      if (fs.existsSync(dir)) {
        fs.rmdirSync(dir, { recursive: true });
      }
    });
    return dir;
  },

  // runAction mocks input with the provided input, captures stdout,
  // sets test db environment variables, and runs the action
  async runAction(inputs) {
    const outputs = module.exports.mockIO(inputs);

    const { run } = require("../index");

    let failure = "";
    let stdout = "";

    const append = (...args) => {
      stdout += args.join(" ") + "\n";
    };

    module.exports.setEnv({
      GRYPE_DB_AUTO_UPDATE: "false",
      GRYPE_DB_VALIDATE_AGE: "false",
      GRYPE_DB_CACHE_DIR: path.join(path.dirname(__dirname), "grype-db"),
    });

    module.exports.mock(core, {
      error: append,
      info: append,
      debug: append,
      setFailed: (...args) => {
        append(...args);
        failure = args.join(" ");
      },
    });

    module.exports.mock(console, {
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
  },
};
