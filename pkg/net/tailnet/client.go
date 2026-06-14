package tailnet

import (
	"context"
	"fmt"
	"net"
	"os"

	"tailscale.com/tsnet"
)

// Server encapsulates the Tailscale node
type Server struct {
	Hostname string
	Server   *tsnet.Server
}

// NewServer creates an ephemeral node on the Tailnet
func NewServer(hostname string) (*Server, error) {
	// Only enabled if TAILSCALE_AUTH_KEY is present
	authKey := os.Getenv("TAILSCALE_AUTH_KEY")
	if authKey == "" {
		return nil, fmt.Errorf("TAILSCALE_AUTH_KEY not found")
	}

	s := &tsnet.Server{
		Hostname:  hostname,
		AuthKey:   authKey,
		Ephemeral: true, // Don't persist this node after exit
		Logf:      func(format string, args ...any) { /* quiet */ },
	}

	return &Server{
		Hostname: hostname,
		Server:   s,
	}, nil
}

// Listen starts a TCP listener on the Tailnet (usually port 80 or 443 inside the mesh)
func (s *Server) Listen(ctx context.Context, addr string) (net.Listener, error) {
	// Ifaddr is ":443", tsnet will try to get a cert from Let's Encrypt for the tailnet domain
	return s.Server.Listen("tcp", addr)
}
