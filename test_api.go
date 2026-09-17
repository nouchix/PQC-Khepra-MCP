package main

import (
	"context"
	"fmt"
	"os"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/stig"
)

func main() {
	key := "ss_token_app_stigviewer_ff08f39852340ac6b6866ee7cdbaa6e1afb2c610b5934486"
	f := stig.NewLiveFetcher(key, "")
	stats, err := f.Stats(context.Background())
	if err != nil {
		fmt.Printf("API Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("API Connected! Total Findings: %d, Benchmarks: %d\n", stats.TotalFindings, stats.TotalBenchmarks)
}
