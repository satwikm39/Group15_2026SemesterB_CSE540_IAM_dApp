const http = require("http");
const path = require("path");
const fs = require("fs/promises");

const ROOT = process.cwd();
const WEB_ROOT = path.join(ROOT, "web");

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
};

function safeResolve(base, target) {
  const resolved = path.normalize(path.join(base, target));
  if (!resolved.startsWith(base)) {
    return null;
  }
  return resolved;
}

async function serveFile(res, filePath) {
  try {
    const content = await fs.readFile(filePath);
    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, { "Content-Type": MIME[ext] || "application/octet-stream" });
    res.end(content);
  } catch {
    res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("Not found");
  }
}

const server = http.createServer(async (req, res) => {
  const requestPath = decodeURIComponent(req.url || "/");

  if (requestPath === "/" || requestPath === "/index.html") {
    return serveFile(res, path.join(WEB_ROOT, "index.html"));
  }

  if (requestPath === "/deployments.json") {
    return serveFile(res, path.join(ROOT, "deployments.json"));
  }

  if (requestPath.startsWith("/web/")) {
    const filePath = safeResolve(WEB_ROOT, requestPath.replace("/web/", ""));
    if (!filePath) {
      res.writeHead(400, { "Content-Type": "text/plain; charset=utf-8" });
      res.end("Invalid path");
      return;
    }
    return serveFile(res, filePath);
  }

  const maybeFile = safeResolve(WEB_ROOT, requestPath.slice(1));
  if (maybeFile) {
    return serveFile(res, maybeFile);
  }

  res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
  res.end("Not found");
});

const port = Number(process.env.PORT || 5174);
server.listen(port, () => {
  console.log(`IAM dashboard running at http://localhost:${port}`);
});
