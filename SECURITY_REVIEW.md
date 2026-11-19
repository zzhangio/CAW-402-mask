# Security Review Notes

## Current Status

This project is a hackathon privacy-payment adapter, not a production privacy wallet.

The intended claim is narrow:

```text
Separate the research-payment note/burner path from future trading wallets.
Enforce provider allowlists and small spend budgets.
Keep local note/recovery material encrypted.
```

It does not currently prove prompt privacy, IP privacy, provider-account privacy, or production-grade
ZK circuit integrity.

## Findings And Mitigations

### Public Default PX402_NOTE_PASSWORD

Finding:

```text
Missing PX402_NOTE_PASSWORD previously fell back to local-dev-password-change-me.
That password protects encrypted notes and recovery blobs.
```

Mitigation:

```text
Fixed in bin/privacy-adapter.js.
New local passwords are generated from 32 random bytes. Supplied passwords and saved passwords must be at least 12 characters and must differ from the old public default.
px402-spike funded legacy scripts use the same rejection.
```

### Remote PRXVT Circuits Without Hash Pinning

Finding:

```text
@prxvt/sdk defaults to downloading wasm/zkey from https://circuits.prxvt.com.
The adapter does not hash-pin those artifacts, so it cannot prove exactly which circuit/proving key
was used.
```

Mitigation / avoidance:

```text
Real spend now requires:
PRXVT_REMOTE_CIRCUITS_ACK=I_UNDERSTAND_UNPINNED_REMOTE_CIRCUITS
```

This is an explicit hackathon-only acknowledgement, not a production fix. A production path should
vendor the wasm/zkey, pin hashes, verify before proving, and ideally pin the verification key against
the deployed verifier contract.

### PRXVT publicSignals Nullifier Ordering

Finding:

```text
The inspected SDK build uses publicSignals[1] for cross-chain attestation nullifierHash and
publicSignals[0] in the returned PaymentResult.nullifierHash.
```

Mitigation / avoidance:

```text
The main adapter is Base-only and selects only Base USDC x402 payment requirements.
It does not use PaymentResult.nullifierHash as spend authority.
Cross-chain / attestor usage is out of scope and should remain disabled until the SDK/circuit public
signal order is audited against the circuit source and onchain verifier.
```

### Missing Resource / Method / Host Binding

Finding:

```text
Budget and Base USDC filtering existed, but provider resource, method, and host were not hard
invariants before payment.
```

Mitigation:

```text
Fixed in bin/privacy-adapter.js.
The adapter now allowlists provider method, origin, and path before probing and again checks the
x402 challenge resource before payment.
```

Current allowlist:

```text
cmc:     GET  https://pro-api.coinmarketcap.com/x402/v3/cryptocurrency/quotes/latest
exa:     POST https://api.exa.ai/search
weather: GET  https://httpay.xyz/api/weather
nansen:  POST https://api.nansen.ai/api/v1/smart-money/{netflow,holdings,perp-trades}
nansen:  POST https://api.nansen.ai/api/v1/tgm/flow-intelligence
```

### Spike Scripts Bypass Main Adapter

Finding:

```text
px402-spike scripts can call sdk.wrapFetch(fetch), depositFast, or other raw SDK paths without the
main adapter's budget, provider allowlist, recovery, and circuit-risk gates.
```

Mitigation:

```text
Funded spike scripts now require:
ALLOW_UNGUARDED_SPIKE_FUNDED=I_UNDERSTAND_SPIKE_BYPASSES_MAIN_ADAPTER
```

Funded notes should use:

```text
npm run privacy -- prepare
npm run demo:market -- --providers cmc,exa --symbol ETH --query "..."
```

### Residual Fund Return Can Re-Link Funds

Finding:

```text
The return path withdraws px402 note balance to a disposable burner and then sweeps USDC to the
CAW Base address.

That sweep is public. It can link the burner that received the private withdrawal to the CAW
wallet, even though it does not reveal the original note contents or provider request body.
```

Mitigation / product stance:

```text
Treat return:caw as treasury reconciliation, not as a privacy-preserving default.
For sensitive flows, prefer spend-down or hold-note modes.
Use return:caw when the operator explicitly values fund recovery/accounting more than avoiding
the public return link.
```

Required product controls:

```text
- show a PUBLIC_RETURN_LINK warning before return:caw --execute;
- require --ack-return-link for return:caw --execute;
- record the return-link tradeoff in the receipt;
- support delayed recovery sweep, because burner balances may appear after the first balance read;
- avoid automatically returning residual funds after every purchase.
```

### Secret Custody For Agent-Controlled Notes

Finding:

```text
PX402_NOTE_PASSWORD controls encrypted note and recovery material. If an LLM agent can read it,
the note can be drained or recovery burners can be exposed through logs, prompts, tool traces, or
model output.
```

New Windows note secret files use DPAPI bound to the current user. Unix-like systems create plaintext secret files with mode `0600` in a user-private directory when the directory is new. The default path is `data/secrets/px402-note-password.json`. Windows still reads legacy version-1 plaintext files. Supply the matching `PX402_NOTE_PASSWORD` and run `secrets:init --materialize-secret-file` to migrate such a file. The CLI publishes complete secret files atomically and refuses to generate a fresh password if it finds notes or recovery blobs in the configured directories.

A same-account process can decrypt DPAPI records or read the Unix secret file. Account isolation, custody, and backup remain the operator’s responsibility. The environment override and secret file give access to the full note password.

### CAW bridge and destinations

The rail runner permits only supported datasets, validates pact IDs from both the CLI and evidence files, and validates decimal amount and timeout arguments before queueing a job. Its Bash command quotes each argument as one literal. Keep write access to the executable bridge inbox and its results limited to trusted operators. CAW return and `--to-caw` recovery require a nonzero `CAW_EVM_ADDRESS`. Funding accepts that variable or an explicit `--to`.

### Run logs and callback

JSONL run logs record command and stage identifiers, run IDs, providers, dataset, status, price, booleans and timings. Use opaque run IDs. Requests, command arguments, error text, and stacks are excluded from these logs. The terminal, shell history, receipts, saved research responses and bridge artifacts have separate retention and exposure risks.

Local Curvy onboarding binds to IPv4 loopback, restricts the Host and browser Origin, and accepts a single successful GET callback with a random 256-bit token that expires after five minutes. Direct browser navigation can omit Origin, so access to the private authentication URL confers callback access. The local wallet file contains signature material and inherits the directory's Windows ACL. The callback validates transport and JSON shape. Curvy's service and SDK supply the identity and signature semantics.

### Dependency audit

On 2026-11-19 the installed `px402-spike` lockfile reported 0 critical, 0 high, 0 moderate and 16 low findings under `npm audit`. The remaining findings propagate through `@prxvt/sdk → circomlibjs → ethers v5 → elliptic`. npm reported no fix for the underlying [elliptic advisory](https://github.com/advisories/GHSA-848j-6mx2-7j84). The lockfile updates viem and undici and overrides the old ws and underscore pins in their affected dependency branches.

## Remaining Production Gaps

```text
No local circuit hash pinning yet.
No independent audit of PRXVT SDK public signal order.
No prompt/IP privacy.
No provider-side identity unlinkability.
No merchant payTo pinning; provider payTo can rotate within an allowlisted resource.
No dedicated signing service, account isolation or note-password rotation command yet.
No automated spend-down policy for residual private-note balances yet.
No packaged one-command installer yet.
```
