const fs = require("fs");
for (const f of process.argv.slice(2)) {
  console.log("dos2unix.js", f);
  let contents = fs.readFileSync(f, { encoding: "utf-8" });
  contents = contents.replace(/\r/g, "");
  fs.writeFileSync(f, contents, { encoding: "utf-8" });
}
