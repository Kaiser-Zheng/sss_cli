package main

import (
	cryptoRand "crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	shamir "sss_cli/shamir"
)

// -------------------- entrypoint --------------------

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "split":
		err = cmdSplit(os.Args[2:])
	case "combine":
		err = cmdCombine(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n", os.Args[1])
		usage()
		os.Exit(2)
	}

	if err != nil {
		// Keep one exit point so deferred zeroization has a chance to run.
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `
Usage:
  %s split   -n <parts> -t <threshold> [-secret <text>] [-in <file>] [-outdir <dir>] [--quiet]
  %s combine (-shares <b64,b64,...> | -files <f1,f2,...>) [-out <file>]

Subcommands:

  split
    -n         Number of shares to generate (2..255)
    -t         Threshold required to reconstruct (2..<=n)
    -secret    Secret provided as a UTF-8 string (mutually exclusive with -in)
    -in        Path to a binary file containing the secret (mutually exclusive with -secret)
    -outdir    If set, writes shares as text files containing Base64 (share_01.b64, ...)
    --quiet    If set, suppresses printing shares to stdout
    (The program performs a quick self-test by recombining a random threshold-sized subset.)

  combine
    -shares    Comma-separated Base64 shares (each one is a single share)
    -files     Comma-separated file paths; each file contains a single Base64 share
    -out       If set, writes the recovered secret to this file; otherwise prints as text
               (If the original secret was binary, you should use -out.)

Notes:
  * Shares are Base64-encoded. Each share decodes to len(secret)+1 bytes (Shamir tag + data).
  * For binary secrets, use 'split -in <file>' and 'combine -out <file>'.
`, filepath.Base(os.Args[0]), filepath.Base(os.Args[0]))
}

// -------------------- zeroization helpers --------------------

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func zero2D(bb [][]byte) {
	for _, b := range bb {
		zero(b)
	}
}

// -------------------- split --------------------

func cmdSplit(args []string) error {
	fs := flag.NewFlagSet("split", flag.ExitOnError)
	var (
		parts     = fs.Int("n", 0, "number of shares")
		threshold = fs.Int("t", 0, "threshold to reconstruct")
		text      = fs.String("secret", "", "secret as text (UTF-8)")
		inFile    = fs.String("in", "", "path to binary secret file")
		outDir    = fs.String("outdir", "", "directory to write Base64 shares")
		quiet     = fs.Bool("quiet", false, "suppress printing shares to stdout")
	)
	_ = fs.Parse(args)

	// Validate inputs
	if *parts < *threshold || *parts < 2 || *threshold < 2 || *parts > 255 || *threshold > 255 {
		return fmt.Errorf("invalid -n / -t values: require 2 <= t <= n <= 255")
	}
	if (*text == "" && *inFile == "") || (*text != "" && *inFile != "") {
		return fmt.Errorf("provide exactly one of -secret or -in")
	}

	// Load secret
	var secret []byte
	var err error
	if *text != "" {
		// NOTE: using []byte(string) makes an immutable string copy first; here
		// we accept it because input came from argv. We zeroize our slice.
		secret = []byte(*text)
	} else {
		secret, err = os.ReadFile(*inFile)
		if err != nil {
			return fmt.Errorf("failed to read -in: %w", err)
		}
	}
	if len(secret) == 0 {
		return errors.New("secret is empty")
	}
	defer zero(secret)

	// Split
	shares, err := shamir.Split(secret, *parts, *threshold)
	if err != nil {
		return fmt.Errorf("split failed: %w", err)
	}
	// Ensure shares are wiped when we return
	defer zero2D(shares)

	// Optional self-test: pick random threshold shares and try combine
	ok, testErr := selfTestCombine(shares, *threshold, secret)
	if !ok {
		return fmt.Errorf("self-test failed: %v", testErr)
	}

	// Output: stdout (unless quiet) and/or files.
	// Avoid materializing Base64 as strings; stream instead.

	if !*quiet {
		fmt.Println("Shares (Base64):")
		for i, s := range shares {
			fmt.Printf("  [%02d] ", i+1)
			enc := base64.NewEncoder(base64.StdEncoding, os.Stdout)
			if _, err := enc.Write(s); err != nil {
				_ = enc.Close()
				return fmt.Errorf("failed to encode share %d to stdout: %w", i+1, err)
			}
			if err := enc.Close(); err != nil {
				return fmt.Errorf("failed to finalize Base64 for share %d: %w", i+1, err)
			}
			fmt.Print("\n")
		}
	}

	if *outDir != "" {
		if err := os.MkdirAll(*outDir, 0o700); err != nil {
			return fmt.Errorf("failed to create outdir: %w", err)
		}
		if runtime.GOOS == "windows" {
			fmt.Fprintln(os.Stderr, "Warning: file mode 0600 is POSIX-only and not enforced on Windows; ensure directory ACLs are restrictive.")
		}
		for i, s := range shares {
			name := filepath.Join(*outDir, fmt.Sprintf("share_%02d.b64", i+1))
			f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
			if err != nil {
				return fmt.Errorf("failed to open %s: %w", name, err)
			}
			enc := base64.NewEncoder(base64.StdEncoding, f)
			if _, err := enc.Write(s); err != nil {
				_ = enc.Close()
				_ = f.Close()
				return fmt.Errorf("failed to encode %s: %w", name, err)
			}
			if err := enc.Close(); err != nil {
				_ = f.Close()
				return fmt.Errorf("failed to finalize %s: %w", name, err)
			}
			if err := f.Close(); err != nil {
				return fmt.Errorf("failed to close %s: %w", name, err)
			}
		}
		fmt.Printf("Wrote %d share files to %s\n", len(shares), *outDir)
	}

	// Compute lengths without creating Base64 strings
	rawLen := len(shares[0])
	b64Len := base64.StdEncoding.EncodedLen(rawLen)
	fmt.Printf("Split OK. n=%d t=%d; share length=%d bytes (raw), %d Base64 chars.\n",
		*parts, *threshold, rawLen, b64Len)
	fmt.Println("Self-test: PASS (random threshold subset successfully recombined)")
	return nil
}

// selfTestCombine takes a random threshold-sized subset, combines, and checks equality.
func selfTestCombine(all [][]byte, threshold int, original []byte) (bool, error) {
	idxs, err := randomDistinctIndices(len(all), threshold)
	if err != nil {
		return false, err
	}
	sub := make([][]byte, 0, threshold)
	for _, i := range idxs {
		sub = append(sub, all[i])
	}
	rec, err := shamir.Combine(sub)
	if err != nil {
		return false, err
	}
	defer zero(rec)
	if !bytesEqual(rec, original) {
		return false, errors.New("recombined secret != original")
	}
	return true, nil
}

func randomDistinctIndices(n, k int) ([]int, error) {
	if k > n {
		return nil, fmt.Errorf("k > n")
	}
	// Crypto-strong sampling via rejection with a set (fine for small k),
	// or you could implement a crypto Fisher–Yates of [0..n).
	seen := make(map[int]struct{}, k)
	for len(seen) < k {
		rb, err := cryptoRand.Int(cryptoRand.Reader, big.NewInt(int64(n)))
		if err != nil {
			return nil, err
		}
		seen[int(rb.Int64())] = struct{}{}
	}
	out := make([]int, 0, k)
	for i := range seen {
		out = append(out, i)
	}
	return out, nil
}

// -------------------- combine --------------------

func cmdCombine(args []string) error {
	fs := flag.NewFlagSet("combine", flag.ExitOnError)
	var (
		shareCSV = fs.String("shares", "", "comma-separated Base64 shares")
		filesCSV = fs.String("files", "", "comma-separated files (each contains one Base64 share)")
		outFile  = fs.String("out", "", "write recovered secret to file (recommended for binary)")
	)
	_ = fs.Parse(args)

	if (*shareCSV == "" && *filesCSV == "") || (*shareCSV != "" && *filesCSV != "") {
		return fmt.Errorf("provide exactly one of -shares or -files")
	}

	var parts [][]byte

	if *filesCSV != "" {
		paths := splitCSV(*filesCSV)
		for _, p := range paths {
			data, err := os.ReadFile(p)
			if err != nil {
				return fmt.Errorf("failed reading %s: %w", p, err)
			}
			// Trim, decode directly, then wipe the file content buffer.
			b64 := strings.TrimSpace(string(data))
			zero(data) // best-effort wipe of file bytes buffer
			if b64 == "" {
				return fmt.Errorf("file %s is empty", p)
			}
			raw, err := base64.StdEncoding.DecodeString(b64)
			// Note: b64 is a string; cannot be zeroized.
			if err != nil {
				return fmt.Errorf("file %s does not contain valid Base64: %w", p, err)
			}
			parts = append(parts, raw)
		}
	} else {
		// -shares mode: we must accept Base64 in argv as strings (cannot zeroize).
		tmp := strings.Split(*shareCSV, ",")
		for i, s := range tmp {
			s = strings.TrimSpace(s)
			if s == "" {
				return fmt.Errorf("share %d is empty", i+1)
			}
			raw, err := base64.StdEncoding.DecodeString(s)
			if err != nil {
				return fmt.Errorf("share %d is not valid Base64: %w", i+1, err)
			}
			parts = append(parts, raw)
		}
	}

	if len(parts) < 2 {
		zero2D(parts)
		return fmt.Errorf("need at least 2 shares to combine")
	}
	defer zero2D(parts)

	secret, err := shamir.Combine(parts)
	if err != nil {
		return fmt.Errorf("combine failed: %w", err)
	}
	defer zero(secret)

	if *outFile != "" {
		if runtime.GOOS == "windows" {
			fmt.Fprintln(os.Stderr, "Warning: file mode 0600 is POSIX-only and not enforced on Windows; ensure directory ACLs are restrictive.")
		}
		if err := os.WriteFile(*outFile, secret, 0o600); err != nil {
			return fmt.Errorf("failed to write -out: %w", err)
		}
		fmt.Printf("Recovered secret written to %s (%d bytes)\n", *outFile, len(secret))
		return nil
	}

	// Print as text; warn if it looks binary.
	if !isLikelyText(secret) {
		fmt.Fprintln(os.Stderr, "Warning: recovered data looks binary. Use -out to write to a file.")
	}
	fmt.Printf("%s\n", string(secret))
	return nil
}

// -------------------- helpers --------------------

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func isLikelyText(b []byte) bool {
	// Very simple heuristic: allow common printable range plus tab/newline/carriage return.
	for _, c := range b {
		if c == 9 || c == 10 || c == 13 {
			continue
		}
		if c < 32 || c > 126 {
			return false
		}
	}
	return true
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
