import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { pathToFileURL } from "node:url";

const authOrigin = "https://app.curvy.box";
const loopback = "127.0.0.1";

export function runLocalAuth(walletPath) {
  const walletDir = path.dirname(walletPath);
  fs.mkdirSync(walletDir, { recursive: true, mode: 0o700 });
  if (fs.existsSync(walletPath)) return Promise.resolve();
  const urlPath = path.join(walletDir, "auth-url.txt");
  const pidPath = path.join(walletDir, "auth-server.pid");
  // Keep state in the callback path so clients can append their own query string.
  const callbackPath = "/auth/callback/" + crypto.randomBytes(32).toString("base64url");
  return new Promise((resolve, reject) => {
    let authority;
    let used = false;
    let expiry;
    let authUrl;
    function finish(error) {
      used = true;
      clearTimeout(expiry);
      server.close();
      try {
        if (authUrl && fs.existsSync(urlPath) && fs.readFileSync(urlPath, "utf8").trim() === authUrl) {
          fs.rmSync(urlPath, { force: true });
          fs.rmSync(pidPath, { force: true });
        }
      } catch (cleanupError) {
        error ||= cleanupError;
      }
      if (error) reject(error);
      else resolve();
    }
    const server = http.createServer({ maxHeaderSize: 16_384 }, (req, res) => {
      res.setHeader("Cache-Control", "no-store");
      res.setHeader("Referrer-Policy", "no-referrer");
      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      const fail = (status, message) => { res.writeHead(status); res.end(message); };
      if (used || req.headers.host !== authority) return fail(403, "Forbidden");
      if (req.headers.origin !== undefined && req.headers.origin !== authOrigin) return fail(403, "Forbidden");
      let url;
      try { url = new URL(req.url, "http://" + authority); } catch { return fail(400, "Invalid callback"); }
      if (url.host !== authority || url.pathname !== callbackPath) return fail(404, "Unknown callback");
      if (req.headers.origin === authOrigin) {
        res.setHeader("Access-Control-Allow-Origin", authOrigin);
        res.setHeader("Vary", "Origin");
      }
      if (req.method === "OPTIONS" && req.headers.origin === authOrigin && req.headers["access-control-request-method"] === "GET") {
        res.setHeader("Access-Control-Allow-Methods", "GET");
        res.writeHead(204).end();
        return;
      }
      if (req.method !== "GET") return fail(405, "GET required");
      const values = url.searchParams.getAll("signatureParams");
      if (values.length !== 1) return fail(400, "Expected one signatureParams value");
      let signature;
      try {
        // Older Curvy clients add an extra layer of URI encoding.
        const raw = values[0].trim();
        signature = JSON.parse(raw.startsWith("{") ? raw : decodeURIComponent(raw));
        if (!signature || typeof signature !== "object" || Array.isArray(signature) || !Object.keys(signature).length) {
          return fail(400, "Invalid signature parameters");
        }
      } catch { return fail(400, "Invalid signature parameters"); }
      used = true;
      try {
        fs.writeFileSync(walletPath, JSON.stringify({ signature }), { flag: "wx", mode: 0o600 });
      } catch {
        fail(409, "Could not create wallet file");
        finish(new Error("Could not create wallet file."));
        return;
      }
      res.end("Authentication successful. You can close this tab.");
      finish();
    });
    server.once("error", finish);
    server.listen(0, loopback, () => {
      authority = loopback + ":" + server.address().port;
      const url = new URL("/auth", authOrigin);
      url.searchParams.set("callback", "http://" + authority + callbackPath);
      authUrl = url.toString();
      try {
        fs.writeFileSync(urlPath, authUrl + "\n", { mode: 0o600 });
        fs.writeFileSync(pidPath, String(process.pid) + "\n", { mode: 0o600 });
      } catch (error) { finish(error); return; }
      console.log("Open this private URL to authenticate:\n" + authUrl);
      expiry = setTimeout(() => finish(new Error("Authentication callback expired.")), 5 * 60_000);
    });
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const walletPath = path.resolve(".curvy", "wallet.json");
  await runLocalAuth(walletPath);
  console.log("Local Curvy wallet available at " + walletPath);
}
