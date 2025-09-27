# Shamir’s Secret Sharing (SSS) – Minimal CLI

A minimal CLI wrapper for Shamir's Secret Sharing, **using the proven implementation from HashiCorp Vault**.

## What it does

* **Split** a secret (text or binary file) into `n` shares with a reconstruction threshold `t`.
* **Combine** any `t` valid shares to recover the original secret.
* Shares are printed/stored as **Base64**, safe for copy/paste and text files.
* A quick self-test runs after splitting to verify that a random threshold subset recombines correctly.

## Project layout

```
.
├── go.mod
├── main.go                # CLI (split/combine)
└── shamir
    ├── shamir.go          # forked from hashicorp/vault
    └── shamir_test.go     # forked from hashicorp/vault
```

## Requirements

* Go 1.20+ (tested with recent Go versions)

## Build

From the module root:

```bash
go build -o sss
```

## Usage

```
sss split   -n <parts> -t <threshold> [-secret <text>] [-in <file>] [-outdir <dir>] [--quiet]
sss combine (-shares <b64,b64,...> | -files <f1,f2,...>) [-out <file>]
```

### Split

Provide **exactly one** of `-secret` (text) or `-in` (binary file).

```bash
# Text secret, print shares and also write them to ./shares
./sss split -n 5 -t 3 -secret "top secret" -outdir shares

# Binary secret from file; quiet stdout, write shares to ./shares_bin
./sss split -n 7 -t 4 -in secret.bin -outdir shares_bin --quiet
```

Notes:

* Constraints: `2 ≤ t ≤ n ≤ 255`; secret must be non-empty.
* Each Base64 share decodes to `len(secret) + 1` bytes (Shamir tag + data).
* After splitting, a self-test recombines a random `t`-subset; if it fails, the program exits with error.
* Implementation details: share X-coordinates are chosen via a **cryptographically secure permutation**; sensitive buffers are **zeroized** best-effort after use; Base64 output to files/stdout is **streamed** to avoid keeping large Base64 strings in memory.

### Combine

Use either `-shares` (comma-separated Base64 strings) **or** `-files` (paths to files that each contain one Base64 share).

```bash
# Combine using three Base64 strings
./sss combine -shares "<b64-1>,<b64-2>,<b64-3>"

# Combine using files; write recovered bytes to a file (recommended for binary)
./sss combine -files "shares/share_01.b64,shares/share_03.b64,shares/share_05.b64" -out recovered.bin
```

If `-out` is omitted, the recovered bytes are printed as text. For binary secrets, **always** use `-out`.

## Security notes

* **Memory handling:** the tool zeroizes sensitive byte slices when possible. However, command-line arguments and Go strings cannot be reliably wiped; prefer `-in`/`-files` over `-secret`/`-shares` for better hygiene.
* **Integrity:** plain SSS provides confidentiality/availability but not authenticity. This CLI does **not** authenticate the secret; combining wrong or tampered shares may yield garbage without error.

## Testing

The fork includes the original unit tests:

```bash
go test ./shamir
```

## License and Attribution

* `shamir/shamir.go` and `shamir/shamir_test.go` are **forked from HashiCorp Vault** v1.20.3 and are subject to the **Business Source License 1.1 (BSL 1.1)**.
* The original HashiCorp Vault code is © 2024 HashiCorp, Inc. under the BSL 1.1 license.
* This project maintains the same BSL 1.1 license terms for the forked components.
* **Important**: The BSL 1.1 allows most use cases including production use, but restricts offering competitive hosted services.

For the complete license terms, see the `LICENSE` file in this repository, which contains the full BSL 1.1 text from the original HashiCorp Vault project.

## Disclaimer

This is an unofficial fork and is not endorsed by or affiliated with HashiCorp, Inc. For official Vault implementations, please visit https://www.vaultproject.io/