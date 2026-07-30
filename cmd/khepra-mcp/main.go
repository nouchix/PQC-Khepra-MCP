package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	khepramcp "github.com/nouchix/PQC-Khepra-MCP/pkg/mcp"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/mcp/kernelports"
)

func main() {
	logger := log.New(os.Stderr, "[khepra-mcp] ", log.LstdFlags|log.Lmicroseconds)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger.Printf("━━━ KHEPRA MCP OSS KERNEL ━━━")
	deps := kernelports.Defaults()

	demarc := &khepramcp.DefaultDemarcGateway{
		StdioIdentity: khepramcp.Identity{
			Subject:   "khepra-mcp-stdio",
			Issuer:    "demarc",
			AgentID:   "local-agent",
			SessionID: "oss-session",
			Scopes:    []string{"*"},
		},
	}

	poly := &khepramcp.DefaultPolymorphicEngine{
		Signer: deps.Signer,
	}

	gateway := khepramcp.NewDefaultMCPGateway()

	router, err := khepramcp.NewRouter(khepramcp.RouterConfig{
		Demarc:         demarc,
		Poly:           poly,
		Gateway:        gateway,
		Attestor:       deps.Attestor,
		License:        deps.License,
		FlightRecorder: deps.Flight,
		Logger:         logger,
	})
	if err != nil {
		logger.Fatalf("Router error: %v", err)
	}

	srv, err := khepramcp.NewHardenedServer(khepramcp.HardenedServerConfig{
		Mode:   khepramcp.TransportStdio,
		Router: router,
		Logger: logger,
	})
	if err != nil {
		logger.Fatalf("Server error: %v", err)
	}

	if err := srv.Run(ctx); err != nil {
		logger.Fatalf("Serve error: %v", err)
	}
}
