jest.mock("@actions/core");
jest.mock("@actions/exec");
jest.mock("@actions/tool-cache");

const core = require("@actions/core");
const path = require("path");
const fs = require("fs");

const contentMergeFixture = require("./fixtures/content-merge.fixture");

// Find all 'content-*.json' files in the directory. dirname should include the full path
function findContent(searchDir) {
  let contentFiles = [];
  let match = /content-.*\.json/;
  var dirItems = fs.readdirSync(searchDir);
  if (dirItems) {
    for (let i = 0; i < dirItems.length; i++) {
      if (match.test(dirItems[i])) {
        contentFiles.push(`${searchDir}/${dirItems[i]}`);
      }
    }
  } else {
    core.debug("no dir content found");
  }

  core.debug(contentFiles.toString());
  return contentFiles;
}

// Load the json content of each file in a list and return them as a list
function loadContent(files) {
  let contents = [];
  if (files) {
    files.forEach((item) => contents.push(JSON.parse(fs.readFileSync(item))));
  }
  return contents;
}

// Merge the multiple content output types into a single array
function mergeResults(contentArray) {
  return contentArray.reduce((merged, n) => merged.concat(n.content), []);
}

describe("unit-tests", () => {
  it("tests merge of outputs into single bill of materials with os-only packages", () => {
    let merged = mergeResults([contentMergeFixture["content-os.json"]]);
    //console.log("os-only output: " +JSON.stringify(merged));
    expect(merged.length).toBeGreaterThan(0);
  });

  it("tests merge of outputs into single bill of materials with all packages", () => {
    let merged = mergeResults([
      contentMergeFixture["content-os.json"],
      contentMergeFixture["content-npm.json"],
      contentMergeFixture["content-gem.json"],
      contentMergeFixture["content-java.json"],
      contentMergeFixture["content-python.json"],
    ]);
    //console.log("merged output: " +JSON.stringify(merged));
    expect(merged.length).toBeGreaterThan(0);
  });

  it("tests finding content files in dir", () => {
    let testPath = path.join(__dirname, "fixtures");

    const mock = jest.spyOn(fs, "readdirSync");
    mock.mockImplementation(() => {
      return Object.keys(contentMergeFixture);
    });

    let contentFiles = findContent(testPath);
    expect(contentFiles.length).toEqual(5);

    mock.mockRestore(); // restore fs.readdirSync()
  });

  it("tests loading content in list", () => {
    const mock = jest.spyOn(fs, "readFileSync");
    mock.mockImplementation((i) => {
      return JSON.stringify(contentMergeFixture[i]);
    });

    let contentFiles = loadContent(Object.keys(contentMergeFixture));
    expect(contentFiles.length).toEqual(5);

    mock.mockRestore(); // restore fs.readFileSync()
  });
});
