const { execFile } = require("child_process");
const { installGrype } = require("../index");

(async () => {
  try {
    const pinnedDB =
      "https://grype.anchore.io/databases/v6/vulnerability-db_v6.0.2_2025-04-01T01:31:39Z_1743480497.tar.zst";
    const path = await installGrype(process.argv[2] || "latest");
    console.log("Installed to:", path);

    execFile(path, ["db", "import", pinnedDB], (error, stdout, stderr) => {
      console.log("Importing db from: ", pinnedDB);
      if (error) {
        console.error("Error running db update:", stderr);
        process.exit(1);
      }
      console.log(stdout);
    });
  } catch (e) {
    console.error("Failed to install or update Grype DB:", e);
    process.exit(1);
  }
})();
