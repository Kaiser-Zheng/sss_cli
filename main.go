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
	"strings"

	shamir "sss_cli/shamir"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "split":
		cmdSplit(os.Args[2:])
	case "combine":
		cmdCombine(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n", os.Args[1])
		usage()
		os.Exit(2)
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

// -------------------- split --------------------

func cmdSplit(args []string) {
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
		fail("invalid -n / -t values: require 2 <= t <= n <= 255")
	}
	if (*text == "" && *inFile == "") || (*text != "" && *inFile != "") {
		fail("provide exactly one of -secret or -in")
	}

	// Load secret
	var secret []byte
	var err error
	if *text != "" {
		secret = []byte(*text)
	} else {
		secret, err = os.ReadFile(*inFile)
		if err != nil {
			fail("failed to read -in: %v", err)
		}
	}
	if len(secret) == 0 {
		fail("secret is empty")
	}

	// Split
	shares, err := shamir.Split(secret, *parts, *threshold)
	if err != nil {
		fail("split failed: %v", err)
	}

	// Optional self-test: pick random threshold shares and try combine
	ok, testErr := selfTestCombine(shares, *threshold, secret)
	if !ok {
		fail("self-test failed: %v", testErr)
	}

	// Output: stdout (unless quiet) and/or files
	b64Shares := make([]string, len(shares))
	for i, s := range shares {
		b64Shares[i] = base64.StdEncoding.EncodeToString(s)
	}

	if !*quiet {
		fmt.Println("Shares (Base64):")
		for i, s := range b64Shares {
			fmt.Printf("  [%02d] %s\n", i+1, s)
		}
	}

	if *outDir != "" {
		if err := os.MkdirAll(*outDir, 0o755); err != nil {
			fail("failed to create outdir: %v", err)
		}
		for i, s := range b64Shares {
			name := filepath.Join(*outDir, fmt.Sprintf("share_%02d.b64", i+1))
			if err := os.WriteFile(name, []byte(s+"\n"), 0o600); err != nil {
				fail("failed to write %s: %v", name, err)
			}
		}
		fmt.Printf("Wrote %d share files to %s\n", len(b64Shares), *outDir)
	}

	fmt.Printf("Split OK. n=%d t=%d; share length=%d bytes (raw), %d Base64 chars.\n",
		*parts, *threshold, len(shares[0]), len(b64Shares[0]))
	fmt.Println("Self-test: PASS (random threshold subset successfully recombined)")
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
	if !bytesEqual(rec, original) {
		return false, errors.New("recombined secret != original")
	}
	return true, nil
}

func randomDistinctIndices(n, k int) ([]int, error) {
	if k > n {
		return nil, fmt.Errorf("k > n")
	}
	// Simple reservoir-like selection using crypto/rand
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

func cmdCombine(args []string) {
	fs := flag.NewFlagSet("combine", flag.ExitOnError)
	var (
		shareCSV = fs.String("shares", "", "comma-separated Base64 shares")
		filesCSV = fs.String("files", "", "comma-separated files (each contains one Base64 share)")
		outFile  = fs.String("out", "", "write recovered secret to file (recommended for binary)")
	)
	_ = fs.Parse(args)

	if (*shareCSV == "" && *filesCSV == "") || (*shareCSV != "" && *filesCSV != "") {
		fail("provide exactly one of -shares or -files")
	}

	var b64Shares []string
	if *shareCSV != "" {
		for _, s := range strings.Split(*shareCSV, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				b64Shares = append(b64Shares, s)
			}
		}
	} else {
		paths := splitCSV(*filesCSV)
		for _, p := range paths {
			data, err := os.ReadFile(p)
			if err != nil {
				fail("failed reading %s: %v", p, err)
			}
			// assume files contain Base64 text; trim spaces/newlines
			b64 := strings.TrimSpace(string(data))
			if b64 == "" {
				fail("file %s is empty", p)
			}
			b64Shares = append(b64Shares, b64)
		}
	}

	if len(b64Shares) < 2 {
		fail("need at least 2 shares to combine")
	}

	parts := make([][]byte, len(b64Shares))
	for i, b64 := range b64Shares {
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			fail("share %d is not valid Base64: %v", i+1, err)
		}
		if len(raw) < 2 {
			fail("share %d too short", i+1)
		}
		parts[i] = raw
	}

	secret, err := shamir.Combine(parts)
	if err != nil {
		fail("combine failed: %v", err)
	}

	if *outFile != "" {
		if err := os.WriteFile(*outFile, secret, 0o600); err != nil {
			fail("failed to write -out: %v", err)
		}
		fmt.Printf("Recovered secret written to %s (%d bytes)\n", *outFile, len(secret))
		return
	}

	// Print as text; warn if it looks binary.
	if !isLikelyText(secret) {
		fmt.Fprintln(os.Stderr, "Warning: recovered data looks binary. Use -out to write to a file.")
	}
	fmt.Printf("%s\n", string(secret))
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
	// constant-time style not necessary here; functional equality is fine
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", args...)
	os.Exit(1)
}
