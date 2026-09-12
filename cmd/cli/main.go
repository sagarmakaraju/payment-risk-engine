package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
)

const defaultBaseURL = "http://localhost:8080"

func getBaseURL() string {
	url := os.Getenv("FS2601_URL")
	if url == "" {
		return defaultBaseURL
	}
	return url
}

func printUsage() {
	fmt.Println(`FS-2601 Payment Authorization & Risk CLI Tool

Usage:
  fs2601-cli <command> [arguments]

Commands:
  health                     Check server health & network status
  balance <account_id>       Query account balance snapshot
  pay <account> <merchant> <amount_usd>
                             Submit an online/offline payment authorization
  network <status>           Toggle partition (ONLINE | DISCONNECTED | RECONNECTED)
  token <account> [amount]   Issue an Ed25519 offline token (default $50 floor)
  allowance <account> <amt>  Pre-allocate offline allowance (Feature 1)
  revoke <account>           Insert account into Compact Cuckoo Filter (Feature 2)
  cuckoo-stats               Inspect Compact Cuckoo Filter memory & FPR stats (Feature 2)
  qr [tamper_mode]           Generate dynamic QR (NONE | EXPIRED | STICKER_MISMATCH | FORGED) (Feature 3)
  reconcile                  Trigger deterministic WAL replay and reconciliation (Feature 4)
  reserve                    Query deficit reserve balance (Feature 5)
  audit                      Verify global double-entry conservation invariant`)
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	baseURL := getBaseURL()

	switch cmd {
	case "health":
		doGet(baseURL + "/api/v1/health")

	case "balance":
		if len(os.Args) < 3 {
			fmt.Println("Usage: fs2601-cli balance <account_id>")
			os.Exit(1)
		}
		doGet(baseURL + "/api/v1/account/" + os.Args[2])

	case "pay":
		if len(os.Args) < 5 {
			fmt.Println("Usage: fs2601-cli pay <account> <merchant> <amount_usd>")
			os.Exit(1)
		}
		amtUSD, err := strconv.ParseFloat(os.Args[4], 64)
		if err != nil {
			fmt.Printf("Invalid amount: %v\n", err)
			os.Exit(1)
		}
		cents := int64(amtUSD * 100)
		body := map[string]interface{}{
			"account_id":  os.Args[2],
			"merchant_id": os.Args[3],
			"terminal_id": "TERM-001",
			"amount":      cents,
		}
		doPost(baseURL+"/api/v1/auth/pay", body)

	case "network":
		if len(os.Args) < 3 {
			fmt.Println("Usage: fs2601-cli network <ONLINE|DISCONNECTED|RECONNECTED>")
			os.Exit(1)
		}
		doPost(baseURL+"/api/v1/network/toggle", map[string]string{"status": os.Args[2]})

	case "token":
		if len(os.Args) < 3 {
			fmt.Println("Usage: fs2601-cli token <account> [max_floor_usd]")
			os.Exit(1)
		}
		floorCents := int64(5000)
		if len(os.Args) >= 4 {
			f, _ := strconv.ParseFloat(os.Args[3], 64)
			floorCents = int64(f * 100)
		}
		doPost(baseURL+"/api/v1/tokens/issue", map[string]interface{}{
			"account_id":       os.Args[2],
			"max_floor_amount": floorCents,
			"duration_sec":     3600,
			"terminal_id":      "TERM-001",
		})

	case "allowance":
		if len(os.Args) < 4 {
			fmt.Println("Usage: fs2601-cli allowance <account> <amount_usd>")
			os.Exit(1)
		}
		amt, _ := strconv.ParseFloat(os.Args[3], 64)
		doPost(baseURL+"/api/v1/ledger/allowance/allocate", map[string]interface{}{
			"account_id": os.Args[2],
			"amount":     int64(amt * 100),
		})

	case "revoke":
		if len(os.Args) < 3 {
			fmt.Println("Usage: fs2601-cli revoke <account>")
			os.Exit(1)
		}
		doPost(baseURL+"/api/v1/revocation/add", map[string]string{"account_id": os.Args[2]})

	case "cuckoo-stats":
		doGet(baseURL + "/api/v1/revocation/stats")

	case "qr":
		tamper := "NONE"
		if len(os.Args) >= 3 {
			tamper = os.Args[2]
		}
		doPost(baseURL+"/api/v1/qr/generate", map[string]string{
			"merchant_id": "MERCHANT-POS-01",
			"terminal_id": "TERM-001",
			"tamper_mode": tamper,
		})

	case "reconcile":
		doPost(baseURL+"/api/v1/reconcile", nil)

	case "reserve":
		doGet(baseURL + "/api/v1/ledger/reserve")

	case "audit":
		doGet(baseURL + "/api/v1/audit/conservation")

	default:
		fmt.Printf("Unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func doGet(url string) {
	resp, err := http.Get(url)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	prettyPrint(resp.Body, resp.StatusCode)
}

func doPost(url string, payload interface{}) {
	var bodyReader io.Reader
	if payload != nil {
		data, _ := json.Marshal(payload)
		bodyReader = bytes.NewReader(data)
	}
	resp, err := http.Post(url, "application/json", bodyReader)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	prettyPrint(resp.Body, resp.StatusCode)
}

func prettyPrint(r io.Reader, statusCode int) {
	data, err := io.ReadAll(r)
	if err != nil {
		fmt.Printf("Read error: %v\n", err)
		return
	}
	var obj interface{}
	if err := json.Unmarshal(data, &obj); err == nil {
		formatted, _ := json.MarshalIndent(obj, "", "  ")
		fmt.Printf("[HTTP %d]\n%s\n", statusCode, string(formatted))
	} else {
		fmt.Printf("[HTTP %d]\n%s\n", statusCode, string(data))
	}
}
