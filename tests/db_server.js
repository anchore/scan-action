const fs = require("fs");
const path = require("path");
const { createHash } = require("crypto");
const http = require("http");
const tar = require("tar");
const { onCleanup, tmpdir } = require("./mocks");

module.exports = {
  listing(date, dbUrl, dbChecksum) {
    return {
      built: date.toISOString(),
      url: dbUrl,
      checksum: "sha256:" + dbChecksum,
      version: 5,
    };
  },

  writeMetadata(tmpdir, date) {
    fs.writeFileSync(
      path.join(tmpdir, "5", "metadata.json"),
      JSON.stringify({
        built: date.toISOString(),
        version: 5,
        checksum:
          "sha256:6957b5a1b93346f9a2b54aaf636a6448a7cd70dc977fa6b3a47d9cbf56289410",
      }),
    );
  },

  sha256(contents) {
    return createHash("sha256").update(contents).digest("hex"); // .digest('base64');
  },

  dbServer(listings, tarGzDb) {
    const server = http.createServer(function (req, res) {
      if (req.url.endsWith(".json")) {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(listings));
      } else if (req.url.endsWith(".tar.gz")) {
        res.writeHead(200, { "Content-Type": "application/octet-stream" });
        res.end(tarGzDb);
      } else {
        res.writeHead(404);
      }
    });

    server.listen();

    onCleanup(async () => {
      await server.close();
    });

    return `http://127.0.0.1:${server.address().port}`;
  },

  async tarGzDir(dir) {
    const tarFile = path.join(tmpdir(), "db.tar.gz");
    await tar.create(
      {
        gzip: true,
        file: tarFile,
        C: dir,
      },
      ["."],
    );
    return fs.readFileSync(tarFile);
  },
};
