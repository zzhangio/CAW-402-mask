# Cobo Agentic Wallet Setup Notes

## CLI Version

```text
caw v0.2.86
```

## Wallet

```text
wallet_id: [redacted: demo wallet identifier]
created_at: 2026-06-11T13:10:55Z
```

## Addresses

### Solana

```json
{
  "address": "[redacted: demo wallet address]",
  "chain_type": "SOL",
  "compatible_chains": [
    "SOL",
    "SOLDEV_SOL"
  ]
}
```

### Ethereum / EVM

```json
{
  "address": "[redacted: demo wallet address]",
  "chain_type": "ETH",
  "compatible_chains": [
    "SETH",
    "BASE_ETH",
    "MATIC",
    "TBASE_SETH",
    "ETH",
    "ARBITRUM_ETH",
    "OPT_ETH",
    "BSC_BNB",
    "AVAXC",
    "HYPEREVM_HYPE"
  ]
}
```

## Demo-Relevant Chain

For the current x402 market-data demo, the relevant CAW address is the EVM address:

```text
[redacted: demo wallet address]
```

This address supports `BASE_ETH`, which is the target chain for the CMC/Exa x402 Base USDC demo.

## Do Not Store Here

Do not store:

- CAW API key;
- `.env` contents;
- private keys;
- owner pairing secrets;
- recovery material.
