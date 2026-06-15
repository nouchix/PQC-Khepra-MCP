// khepra-admin — license management CLI for NouchiX operators
//
// Usage:
//   khepra-admin license list   [--tier sovereign] [--status active]
//   khepra-admin license status --key KHRPA-XXXX-XXXX-XXXX-XXXX
//   khepra-admin license revoke --key KHRPA-XXXX-XXXX-XXXX-XXXX [--reason "..."]
//   khepra-admin license reissue --key KHRPA-XXXX-XXXX-XXXX-XXXX
//   khepra-admin license export  [--since 2026-01-01] [--format csv|json]
//   khepra-admin keygen          --output keys/khepra_signing
//
// Requires env vars:
//   SUPABASE_URL
//   SUPABASE_SERVICE_ROLE_KEY

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "license":
		if len(os.Args) < 3 {
			printUsage()
			os.Exit(1)
		}
		switch os.Args[2] {
		case "list":
			cmdList(os.Args[3:])
		case "status":
			cmdStatus(os.Args[3:])
		case "revoke":
			cmdRevoke(os.Args[3:])
		case "export":
			cmdExport(os.Args[3:])
		default:
			fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n", os.Args[2])
			os.Exit(1)
		}
	case "keygen":
		cmdKeygen(os.Args[2:])
	case "version":
		fmt.Printf("khepra-admin %s\n", version)
	default:
		printUsage()
		os.Exit(1)
	}
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

func cmdList(args []string) {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	tier   := fs.String("tier", "", "Filter by tier (community|sovereign|pharaoh)")
	status := fs.String("status", "active", "Filter by status (active|revoked|expired)")
	fs.Parse(args)

	filters := url.Values{}
	filters.Set("select", "license_key,tier,customer_id,expires_at,revoked_at,created_at")
	filters.Set("order", "created_at.desc")
	if *tier != "" {
		filters.Set("tier", "eq."+*tier)
	}
	switch *status {
	case "active":
		filters.Set("revoked_at", "is.null")
		filters.Set("expires_at", "gt."+time.Now().Format(time.RFC3339))
	case "revoked":
		filters.Set("revoked_at", "not.is.null")
	case "expired":
		filters.Set("expires_at", "lt."+time.Now().Format(time.RFC3339))
	}

	data := supabaseGet("licenses", filters)
	prettyPrint(data)
}

func cmdStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	key := fs.String("key", "", "License key (KHRPA-...)")
	fs.Parse(args)
	if *key == "" {
		fmt.Fprintln(os.Stderr, "--key required")
		os.Exit(1)
	}

	filters := url.Values{}
	filters.Set("license_key", "eq."+*key)
	data := supabaseGet("licenses", filters)
	prettyPrint(data)
}

func cmdRevoke(args []string) {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	key    := fs.String("key", "", "License key (KHRPA-...)")
	reason := fs.String("reason", "admin_revoked", "Revocation reason")
	fs.Parse(args)
	if *key == "" {
		fmt.Fprintln(os.Stderr, "--key required")
		os.Exit(1)
	}

	body := fmt.Sprintf(`{"revoked_at":"%s","revoke_reason":"%s"}`,
		time.Now().Format(time.RFC3339), *reason)
	supabasePatch("licenses", "license_key=eq."+*key, body)
	fmt.Printf("✅ License %s revoked (%s)\n", *key, *reason)
}

func cmdExport(args []string) {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	since  := fs.String("since", "", "Export licenses created since date (RFC3339 or YYYY-MM-DD)")
	format := fs.String("format", "json", "Output format: json|csv")
	fs.Parse(args)

	filters := url.Values{}
	filters.Set("select", "license_key,tier,customer_id,stripe_sub_id,issued_at,expires_at,revoked_at")
	filters.Set("order", "created_at.asc")
	if *since != "" {
		filters.Set("created_at", "gte."+*since)
	}
	if *format == "csv" {
		filters.Set("", "") // Supabase returns CSV with Accept: text/csv
	}

	data := supabaseGet("licenses", filters)
	fmt.Println(string(data))
}

func cmdKeygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	output := fs.String("output", "keys/khepra_signing", "Output path prefix (no extension)")
	fs.Parse(args)

	// TODO: Generate actual ML-DSA-65 keypair using cloudflare/circl
	// import "github.com/cloudflare/circl/sign/mldsa/mldsa65"
	// pub, priv, _ := mldsa65.GenerateKey(rand.Reader)
	fmt.Printf("⚠️  ML-DSA-65 keygen not yet implemented — integrate cloudflare/circl\n")
	fmt.Printf("   Output will be: %s.pub and %s.priv\n", *output, *output)
	fmt.Printf("   Set KHEPRA_SIGNING_KEY_B64 in Supabase secrets with base64(%s.priv)\n", *output)
}

// ---------------------------------------------------------------------------
// Supabase REST helpers
// ---------------------------------------------------------------------------

func supabaseURL() string {
	u := os.Getenv("SUPABASE_URL")
	if u == "" {
		fmt.Fprintln(os.Stderr, "SUPABASE_URL not set")
		os.Exit(1)
	}
	return strings.TrimRight(u, "/")
}

func supabaseKey() string {
	k := os.Getenv("SUPABASE_SERVICE_ROLE_KEY")
	if k == "" {
		fmt.Fprintln(os.Stderr, "SUPABASE_SERVICE_ROLE_KEY not set")
		os.Exit(1)
	}
	return k
}

func supabaseGet(table string, filters url.Values) []byte {
	req, _ := http.NewRequest("GET",
		fmt.Sprintf("%s/rest/v1/%s?%s", supabaseURL(), table, filters.Encode()), nil)
	req.Header.Set("apikey", supabaseKey())
	req.Header.Set("Authorization", "Bearer "+supabaseKey())
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "request failed:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return data
}

func supabasePatch(table, filter, body string) {
	req, _ := http.NewRequest("PATCH",
		fmt.Sprintf("%s/rest/v1/%s?%s", supabaseURL(), table, filter),
		strings.NewReader(body))
	req.Header.Set("apikey", supabaseKey())
	req.Header.Set("Authorization", "Bearer "+supabaseKey())
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Prefer", "return=minimal")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "request failed:", err)
		os.Exit(1)
	}
	resp.Body.Close()
}

func prettyPrint(data []byte) {
	var v any
	json.Unmarshal(data, &v)
	out, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(out))
}

func printUsage() {
	fmt.Print(`khepra-admin ` + version + `

Usage:
  khepra-admin license list    [--tier sovereign|pharaoh] [--status active|revoked|expired]
  khepra-admin license status  --key KHRPA-XXXX-XXXX-XXXX-XXXX
  khepra-admin license revoke  --key KHRPA-XXXX-XXXX-XXXX-XXXX [--reason "..."]
  khepra-admin license export  [--since 2026-01-01] [--format json|csv]
  khepra-admin keygen          [--output keys/khepra_signing]
  khepra-admin version

Env vars:
  SUPABASE_URL              Supabase project URL
  SUPABASE_SERVICE_ROLE_KEY Supabase service role key (admin access)
`)
}
