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

The local console binds to 127.0.0.1:8787 by default. It has no login because it is not meant to be exposed publicly. It refuses public binds unless --unsafe-public-bind is passed.

It does not probe RPC endpoints yet. The status pages only use local files and local command detection.
