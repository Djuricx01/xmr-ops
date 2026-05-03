# xmr-ops

`xmr-ops` is a local ops helper for Monero merchant deployments. It audits local compose, env, proxy, and wallet-looking files for deployment posture around `monerod`, `monero-wallet-rpc`, MoneroPay, BTCPay Monero setups, reverse proxies, and webhooks.

It is not a vulnerability scanner, blockchain analysis tool, hosted service, payment processor, wallet tool, or replacement for MoneroPay or BTCPay. It does not touch wallets, keys, seed phrases, private spend keys, funds, firewall rules, or system config.

Checks are local and conservative. If the tool cannot prove something from local evidence, it reports `REVIEW`, `not detected`, or asks for manual review.

Build:

```sh
go build ./cmd/xmr-ops
```

Audit:

```sh
xmr-ops audit --root ./testdata/example-bad
```

JSON:

```sh
xmr-ops audit --root ./testdata/example-bad --json
```

Local console:

```sh
xmr-ops serve --root ./testdata/example-bad --addr 127.0.0.1:8787
```

The console binds to `127.0.0.1:8787` by default and has no authentication in v0. It refuses public binds unless `--unsafe-public-bind` is passed. RPC probing is intentionally left out in v0; status pages use local files and local command detection only.
