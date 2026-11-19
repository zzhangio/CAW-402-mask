import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import { fileURLToPath } from "node:url";
import test from "node:test";

const root = fileURLToPath(new URL("..", import.meta.url));
const cli = path.join(root, "bin/privacy-adapter.js");
const rail = path.join(root, "scripts/run-nansen-rail.mjs");

function fixture(t) {
  fs.mkdirSync(path.join(root, "data"), { recursive: true });
  const dir = fs.mkdtempSync(path.join(root, "data/recording-security-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

function run(file, args, dir, extra = {}) {
  return spawnSync(process.execPath, [file, ...args], {
    cwd: dir, encoding: "utf8", timeout: 30_000,
    env: { ...process.env, PRIVATE_KEY: randomBytes(32).toString("hex"), PX402_NOTE_PASSWORD: "",
      PX402_NOTE_SECRET_FILE: path.join(dir, "secret.json"), NOTE_DIR: path.join(dir, "notes"),
      RUN_LOG_DIR: path.join(dir, "logs"), RECOVERY_DIR: path.join(dir, "recovery"),
      CAW_EVM_ADDRESS: "", RUN_ID: "fixture", ...extra },
  });
}

test("new secret survives reopen and legacy records retain their password during migration", t => {
  const dir = fixture(t);
  const file = path.join(dir, "secret.json");
  const password = randomBytes(32).toString("hex");
  const init = () => run(cli, ["secrets:init"], dir);
  const first = init();
  assert.equal(first.status, 0, first.stderr);
  assert.equal(JSON.parse(first.stdout).noteSecretCreated, true);
  assert.equal(JSON.parse(init().stdout).noteSecretCreated, false);
  if (process.platform === "win32") assert.equal(JSON.parse(fs.readFileSync(file)).password, undefined);
  fs.writeFileSync(file, JSON.stringify({ version: 1, password }));
  assert.equal(JSON.parse(init().stdout).notePasswordSource, "plaintext_secret_file");
  const materialize = (value) => run(cli, ["secrets:init", "--materialize-vault"], dir, { PX402_NOTE_PASSWORD: value });
  assert.equal(materialize(randomBytes(32).toString("hex")).status, 1);
  const migrated = materialize(password);
  assert.equal(migrated.status, 0, migrated.stderr);
  assert.ok(!migrated.stdout.includes(password));
  assert.equal(materialize(password).status, 0);
  if (process.platform === "win32") assert.ok(!fs.readFileSync(file, "utf8").includes(password));
  fs.unlinkSync(file);
  fs.mkdirSync(path.join(dir, "recovery"));
  fs.writeFileSync(path.join(dir, "recovery/recovery-fixture.json"), "{}");
  assert.equal(init().status, 1);
  assert.ok(!fs.existsSync(file));
});

test("run logs omit arguments, query strings, error text and arbitrary filenames", t => {
  const dir = fixture(t);
  const marker = "fixture-private-query-text";
  const env = { PX402_NOTE_PASSWORD: randomBytes(32).toString("hex") };
  assert.equal(run(cli, ["recover:list", "--query", marker, marker], dir, env).status, 0);
  assert.equal(run(cli, ["recover:sweep", "--file", marker], dir, env).status, 1);
  const log = fs.readFileSync(path.join(dir, "logs/fixture.jsonl"), "utf8");
  assert.ok(log.includes("command_start") && log.includes("command_error"));
  assert.ok(!log.includes(marker) && !log.includes("stack"));
  assert.equal(run(cli, ["return:caw"], dir, env).status, 1);
  assert.match(run(cli, ["recover:sweep", "--to-caw"], dir, env).stderr, /CAW_EVM_ADDRESS/);
  assert.match(run(path.join(root, "scripts/fund-caw-base.mjs"), [], dir).stderr, /CAW_EVM_ADDRESS/);
});

test("bridge validates all caller-controlled arguments before creating an inbox job", t => {
  const dir = fixture(t);
  const scripts = path.join(dir, "operator's workspace", "hackathon", "scripts");
  fs.mkdirSync(scripts, { recursive: true });
  const copy = path.join(scripts, "run-nansen-rail.mjs");
  fs.copyFileSync(rail, copy);
  const inbox = path.join(scripts, "../caw-bridge/inbox");
  const base = ["--rail", "caw-native", "--dry-run", "--pact-id", "pact-test-123"];
  for (const [key, value] of [["pact-id", "two words"], ["pact-id", "-bad"], ["max-amount", "1.2"],
    ["caw-timeout", "-1"], ["timeout-ms", "0"], ["dataset", "constructor"]]) {
    assert.equal(run(copy, [...base, "--" + key, value], dir).status, 1);
    assert.ok(!fs.existsSync(inbox));
  }
  const result = run(copy, [...base, "--timeout-ms", "1"], dir);
  assert.equal(JSON.parse(result.stdout).classification, "bridge_timeout");
  const [job] = fs.readdirSync(inbox);
  const bash = fs.readFileSync(path.join(inbox, job), "utf8");
  assert.ok(bash.includes("operator'\\''s workspace"));
  assert.ok(bash.includes("'pact-test-123'") && bash.includes("'--dry-run'"));
});

test("Curvy requires a valid local callback and consumes its state once", async t => {
  const dir = fixture(t);
  const server = spawn(process.execPath, [path.join(root, "scripts/curvy-auth-server.mjs")], {
    cwd: dir, stdio: ["ignore", "pipe", "pipe"],
  });
  const exited = once(server, "exit");
  try {
    await once(server.stdout, "data");
    const walletFile = path.join(dir, ".curvy/wallet.json");
    const auth = new URL(fs.readFileSync(path.join(dir, ".curvy/auth-url.txt"), "utf8").trim());
    const callback = new URL(auth.searchParams.get("callback"));
    assert.equal(callback.hostname, "127.0.0.1");
    callback.searchParams.set("signatureParams", JSON.stringify({ fixture: true }));
    const unknown = new URL(callback);
    unknown.pathname = "/auth/callback";
    assert.equal((await fetch(unknown)).status, 404);
    assert.equal((await fetch(callback, { headers: { Origin: "https://example.invalid" } })).status, 403);
    assert.ok(!fs.existsSync(walletFile));
    const result = await fetch(callback, { headers: { Origin: "https://app.curvy.box" } });
    assert.equal(result.status, 200);
    assert.equal(result.headers.get("access-control-allow-origin"), "https://app.curvy.box");
    assert.deepEqual(JSON.parse(fs.readFileSync(walletFile)), { signature: { fixture: true } });
    assert.equal((await exited)[0], 0);
    await assert.rejects(fetch(callback));
    assert.ok(!fs.existsSync(path.join(dir, ".curvy/auth-url.txt")));
  } finally {
    if (server.exitCode === null && server.signalCode === null) { server.kill(); await exited; }
  }
});
