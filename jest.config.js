module.exports = {
  setupFiles: ["<rootDir>/.jest/setEnvVars.js"],
  verbose: true,
  testPathIgnorePatterns: ["action.test.js"],
  reporters: [["jest-summary-reporter", { failuresOnly: false }]],
};
