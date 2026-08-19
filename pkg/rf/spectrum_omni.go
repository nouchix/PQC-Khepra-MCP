package rf

import (
    "encoding/json"
    "fmt"
    "net"
    "os"
    "time"
)

// SpectralFinding represents the data produced by the C++ SpectralEngine.
type SpectralFinding struct {
    Timestamp int64  `json:"timestamp"`
    Data      []byte `json:"data"`
    // Additional fields can be added as needed.
}

// SpectralEngineClient defines the contract for sending findings to the C++ daemon.
type SpectralEngineClient interface {
    SubmitFinding(finding SpectralFinding) error
}

// UnixSocketClient implements SpectralEngineClient using a Unix domain socket.
type UnixSocketClient struct {
    socketPath string
    timeout    time.Duration
}

// NewUnixSocketClient creates a new client with the given socket path.
func NewUnixSocketClient(path string) *UnixSocketClient {
    return &UnixSocketClient{socketPath: path, timeout: 5 * time.Second}
}

// SubmitFinding marshals the finding to JSON and sends it over the Unix socket.
func (c *UnixSocketClient) SubmitFinding(finding SpectralFinding) error {
    conn, err := net.DialTimeout("unix", c.socketPath, c.timeout)
    if err != nil {
        return fmt.Errorf("dial unix socket: %w", err)
    }
    defer conn.Close()

    payload, err := json.Marshal(finding)
    if err != nil {
        return fmt.Errorf("marshal finding: %w", err)
    }

    if _, err := conn.Write(payload); err != nil {
        return fmt.Errorf("write to socket: %w", err)
    }

    // Optional ACK read.
    ack := make([]byte, 2)
    conn.SetReadDeadline(time.Now().Add(c.timeout))
    if _, err := conn.Read(ack); err != nil {
        // ignore if daemon does not send ACK
        return nil
    }
    return nil
}

// RFOmniBridge integrates the Go service with the SpectralEngine.
type RFOmniBridge struct {
    ThresholdDBM float64
    client       SpectralEngineClient
    // other fields omitted.
}

// NewRFOmniBridge creates a new bridge.
func NewRFOmniBridge(threshold float64, socketPath string) *RFOmniBridge {
    return &RFOmniBridge{ThresholdDBM: threshold, client: NewUnixSocketClient(socketPath)}
}

// ProcessFinding sends a spectral finding to the daemon.
func (b *RFOmniBridge) ProcessFinding(data []byte) error {
    f := SpectralFinding{Timestamp: time.Now().Unix(), Data: data}
    return b.client.SubmitFinding(f)
}

func socketPathFromEnv() string {
    if p := os.Getenv("SPECTRAL_SOCKET"); p != "" {
        return p
    }
    return "/tmp/spectral_engine.sock"
}

func DefaultBridge(threshold float64) *RFOmniBridge {
    return NewRFOmniBridge(threshold, socketPathFromEnv())
}
