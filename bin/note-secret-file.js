import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

// Pass only base64 bytes through stdin. The PowerShell program contains no caller data.
function dpapi(operation, bytes) {
  const script = `$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Security
$inputBytes=[Convert]::FromBase64String([Console]::In.ReadToEnd())
$result=[Security.Cryptography.ProtectedData]::${operation}($inputBytes,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
[Console]::Write([Convert]::ToBase64String($result))`;
  const executable = path.join(process.env.SystemRoot, "System32/WindowsPowerShell/v1.0/powershell.exe");
  const result = spawnSync(executable, ["-NoProfile", "-NonInteractive", "-Command", script], {
    input: bytes.toString("base64"), encoding: "utf8", windowsHide: true, timeout: 15_000,
  });
  if (result.error || result.status !== 0 || !result.stdout) {
    throw new Error("Windows DPAPI failed. Use the original Windows account or supply PX402_NOTE_PASSWORD.");
  }
  return Buffer.from(result.stdout, "base64");
}

export function readSecretFile(file) {
  const stored = JSON.parse(fs.readFileSync(file, "utf8"));
  if (stored.version === 1 && typeof stored.password === "string") {
    return { password: stored.password, source: "plaintext_secret_file" };
  }
  if (stored.version !== 2 || stored.protection !== "windows-dpapi-current-user") {
    throw new Error("Unsupported note secret file format.");
  }
  if (process.platform !== "win32") throw new Error("Open the note secret with its original Windows account.");
  return {
    password: dpapi("Unprotect", Buffer.from(stored.ciphertext, "base64")).toString("utf8"),
    source: "windows_dpapi",
  };
}

// Publish a complete file atomically. Concurrent first-time callers adopt the winner.
export function writeSecretFile(file, password, overwrite = false) {
  const record = process.platform === "win32"
    ? { version: 2, protection: "windows-dpapi-current-user", ciphertext: dpapi("Protect", Buffer.from(password)).toString("base64") }
    : { version: 1, password };
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const lock = file + ".lock";
  const temp = file + "." + crypto.randomUUID() + ".tmp";
  const deadline = Date.now() + 5_000;
  const sleepWord = new Int32Array(new SharedArrayBuffer(4));
  while (true) {
    try {
      fs.closeSync(fs.openSync(lock, "wx", 0o600));
      break;
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
      if (!overwrite && fs.existsSync(file)) return false;
      if (Date.now() >= deadline) throw new Error("Note secret file is locked. Verify no writer is running before removing the .lock file.");
      Atomics.wait(sleepWord, 0, 0, 40);
    }
  }
  try {
    if (!overwrite && fs.existsSync(file)) return false;
    fs.writeFileSync(temp, JSON.stringify(record), { flag: "wx", mode: 0o600 });
    fs.renameSync(temp, file);
    return true;
  } finally {
    try { fs.rmSync(temp, { force: true }); }
    finally { fs.unlinkSync(lock); }
  }
}
