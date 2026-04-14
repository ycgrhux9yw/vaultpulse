# vaultpulse

A lightweight CLI for auditing HashiCorp Vault secret TTLs and rotation schedules.

---

## Installation

```bash
go install github.com/yourusername/vaultpulse@latest
```

Or download a pre-built binary from the [releases page](https://github.com/yourusername/vaultpulse/releases).

---

## Usage

Set your Vault address and token, then run an audit:

```bash
export VAULT_ADDR="https://vault.example.com"
export VAULT_TOKEN="s.yourtoken"

vaultpulse audit --path secret/
```

### Example Output

```
PATH                          TTL        EXPIRES IN    STATUS
secret/data/db-credentials    24h        2h 14m        ⚠️  Expiring Soon
secret/data/api-keys          720h       29d 6h        ✅  Healthy
secret/data/tls-cert          8760h      EXPIRED       ❌  Expired
```

### Common Flags

| Flag | Description |
|------|-------------|
| `--path` | Vault secret path to audit |
| `--warn-threshold` | Warn when TTL is below this duration (default: `24h`) |
| `--output` | Output format: `table`, `json`, or `csv` |
| `--recursive` | Recursively scan all secrets under the given path |

```bash
# Export results as JSON
vaultpulse audit --path secret/ --output json > report.json

# Scan recursively with a custom warning threshold
vaultpulse audit --path secret/ --recursive --warn-threshold 48h
```

---

## Requirements

- Go 1.21+
- HashiCorp Vault 1.10+
- A valid Vault token with `read` and `list` permissions on the target path

---

## License

MIT © [yourusername](https://github.com/yourusername)