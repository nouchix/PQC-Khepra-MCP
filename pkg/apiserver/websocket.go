package apiserver

import (
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// WebSocketHub manages WebSocket connections and message broadcasting
type WebSocketHub struct {
	// Registered clients grouped by channel type
	scanClients    map[*WebSocketClient]bool
	dagClients     map[*WebSocketClient]bool
	licenseClients map[*WebSocketClient]bool

	// Broadcast channels for each message type
	scanBroadcast    chan *WebSocketMessage
	dagBroadcast     chan *WebSocketMessage
	licenseBroadcast chan *WebSocketMessage

	// Client registration/unregistration
	register   chan *WebSocketClient
	unregister chan *WebSocketClient

	mu sync.RWMutex
}

// WebSocketClient represents a connected WebSocket client
type WebSocketClient struct {
	hub     *WebSocketHub
	conn    *websocket.Conn
	send    chan []byte
	channel string // "scans", "dag", "license"
}

// NewWebSocketHub creates a new WebSocket hub
func NewWebSocketHub() *WebSocketHub {
	return &WebSocketHub{
		scanClients:      make(map[*WebSocketClient]bool),
		dagClients:       make(map[*WebSocketClient]bool),
		licenseClients:   make(map[*WebSocketClient]bool),
		scanBroadcast:    make(chan *WebSocketMessage, 256),
		dagBroadcast:     make(chan *WebSocketMessage, 256),
		licenseBroadcast: make(chan *WebSocketMessage, 256),
		register:         make(chan *WebSocketClient),
		unregister:       make(chan *WebSocketClient),
	}
}

// Run starts the WebSocket hub event loop
func (h *WebSocketHub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			switch client.channel {
			case "scans":
				h.scanClients[client] = true
			case "dag":
				h.dagClients[client] = true
			case "license":
				h.licenseClients[client] = true
			}
			h.mu.Unlock()
			log.Printf("WebSocket client registered: channel=%s, total=%d", client.channel, h.ClientCount(client.channel))

		case client := <-h.unregister:
			h.mu.Lock()
			switch client.channel {
			case "scans":
				if _, ok := h.scanClients[client]; ok {
					delete(h.scanClients, client)
					close(client.send)
				}
			case "dag":
				if _, ok := h.dagClients[client]; ok {
					delete(h.dagClients, client)
					close(client.send)
				}
			case "license":
				if _, ok := h.licenseClients[client]; ok {
					delete(h.licenseClients, client)
					close(client.send)
				}
			}
			h.mu.Unlock()
			log.Printf("WebSocket client unregistered: channel=%s, total=%d", client.channel, h.ClientCount(client.channel))

		case message := <-h.scanBroadcast:
			h.broadcastToClients(h.scanClients, message)

		case message := <-h.dagBroadcast:
			h.broadcastToClients(h.dagClients, message)

		case message := <-h.licenseBroadcast:
			h.broadcastToClients(h.licenseClients, message)
		}
	}
}

// broadcastToClients sends a message to all clients in a channel
func (h *WebSocketHub) broadcastToClients(clients map[*WebSocketClient]bool, message *WebSocketMessage) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	data, err := json.Marshal(message)
	if err != nil {
		log.Printf("Error marshaling WebSocket message: %v", err)
		return
	}

	for client := range clients {
		select {
		case client.send <- data:
		default:
			// Client's send channel is full, close it
			close(client.send)
			delete(clients, client)
		}
	}
}

// BroadcastScanUpdate broadcasts a scan update to all scan clients
func (h *WebSocketHub) BroadcastScanUpdate(data map[string]interface{}) {
	message := &WebSocketMessage{
		Type:      "scan_update",
		Timestamp: time.Now(),
		Data:      data,
	}
	select {
	case h.scanBroadcast <- message:
	default:
		log.Println("Scan broadcast channel full, dropping message")
	}
}

// BroadcastDAGUpdate broadcasts a DAG update to all DAG clients
func (h *WebSocketHub) BroadcastDAGUpdate(data map[string]interface{}) {
	message := &WebSocketMessage{
		Type:      "dag_update",
		Timestamp: time.Now(),
		Data:      data,
	}
	select {
	case h.dagBroadcast <- message:
	default:
		log.Println("DAG broadcast channel full, dropping message")
	}
}

// BroadcastLicenseUpdate broadcasts a license update to all license clients
func (h *WebSocketHub) BroadcastLicenseUpdate(data map[string]interface{}) {
	message := &WebSocketMessage{
		Type:      "license_update",
		Timestamp: time.Now(),
		Data:      data,
	}
	select {
	case h.licenseBroadcast <- message:
	default:
		log.Println("License broadcast channel full, dropping message")
	}
}

// BroadcastToChannel broadcasts a message to a specific channel
// Supports: "scans", "dag", "license"
func (h *WebSocketHub) BroadcastToChannel(channel string, data map[string]interface{}) {
	message := &WebSocketMessage{
		Type:      channel + "_update",
		Timestamp: time.Now(),
		Data:      data,
	}

	switch channel {
	case "scans":
		select {
		case h.scanBroadcast <- message:
		default:
			log.Println("Scan broadcast channel full, dropping message")
		}
	case "dag":
		select {
		case h.dagBroadcast <- message:
		default:
			log.Println("DAG broadcast channel full, dropping message")
		}
	case "license":
		select {
		case h.licenseBroadcast <- message:
		default:
			log.Println("License broadcast channel full, dropping message")
		}
	default:
		log.Printf("Unknown WebSocket channel: %s", channel)
	}
}

// ClientCount returns the number of connected clients for a channel
func (h *WebSocketHub) ClientCount(channel string) int {
	h.mu.RLock()
	defer h.mu.RUnlock()

	switch channel {
	case "scans":
		return len(h.scanClients)
	case "dag":
		return len(h.dagClients)
	case "license":
		return len(h.licenseClients)
	default:
		return 0
	}
}

// readPump reads messages from the WebSocket connection
func (c *WebSocketClient) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, _, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket read error: %v", err)
			}
			break
		}
		// We don't expect clients to send messages, just ignore them
	}
}

// writePump writes messages from the hub to the WebSocket connection
func (c *WebSocketClient) writePump() {
	ticker := time.NewTicker(54 * time.Second)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				// Hub closed the channel
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			// Add queued messages to the current WebSocket message
			n := len(c.send)
			for i := 0; i < n; i++ {
				w.Write([]byte{'\n'})
				w.Write(<-c.send)
			}

			if err := w.Close(); err != nil {
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// ServeWebSocket handles WebSocket upgrade and client registration
func (h *WebSocketHub) ServeWebSocket(conn *websocket.Conn, channel string) {
	client := &WebSocketClient{
		hub:     h,
		conn:    conn,
		send:    make(chan []byte, 256),
		channel: channel,
	}

	h.register <- client

	// Start read and write pumps in goroutines
	go client.writePump()
	go client.readPump()
}
