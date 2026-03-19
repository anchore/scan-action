import * as core from "@actions/core";
import * as cache from "@actions/cache";
import {
  grypeVersion,
  installGrype,
  run,
  updateDbWithCache,
} from "./action.js";

const entrypoint = core.getInput("run");
switch (entrypoint) {
  case "download-grype": {
    await installGrype(grypeVersion).then(async (path) => {
      core.info(`Downloaded Grype to: ${path}`);
      core.setOutput("cmd", path);

      // optionally restore, update and cache the db
      if (
        cache.isFeatureAvailable() &&
        (core.getInput("cache-db") || "").toLowerCase() === "true"
      ) {
        await updateDbWithCache(path);
      }
    });
    break;
  }
  default: {
    await run().then();
  }
}
