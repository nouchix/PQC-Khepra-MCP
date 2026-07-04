// Package mcp — local-loopback live attestation viewer.
//
// LiveViewer is NOT the HTTP/SSE transport (transport_http.go) and is
// independent of KHEPRA_HTTP_PORT / the air-gap transport switch in
// cmd/khepra-mcp/main.go. It exists purely to make the signed DAG/attestation
// trail visible in real time while khepra-mcp talks to its MCP client (Claude
// Desktop, Cline, etc.) over stdio, exactly as in sovereign mode today.
//
// It binds 127.0.0.1 only and never accepts a non-loopback bind address, so
// enabling it does not change the network/egress posture of a sovereign
// deployment: nothing leaves the machine, no external client can connect.
package mcp

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
)

// LiveViewer broadcasts MCPEvents to connected SSE clients on a loopback port.
type LiveViewer struct {
	mu        sync.Mutex
	clients   map[chan []byte]bool
	graphPage []byte // dag-viewer.html contents, if loaded; nil falls back to the built-in terminal page
}

// NewLiveViewer creates an empty broadcaster.
func NewLiveViewer() *LiveViewer {
	return &LiveViewer{clients: make(map[chan []byte]bool)}
}

// LoadGraphPage reads dag-viewer.html (the full 3D DAG/CMMC viewer) from disk
// and serves it at "/" instead of the built-in terminal-style page, same-origin
// with /events so EventSource works without any CORS configuration. Safe to
// call with a path that doesn't exist — it just leaves the built-in page active.
func (v *LiveViewer) LoadGraphPage(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	v.mu.Lock()
	v.graphPage = data
	v.mu.Unlock()
	return nil
}

// Push is an EventEmitter hook (see EventEmitter.AddHook) — call it with
// router.Events().AddHook(viewer.Push) to wire live attestation events.
func (v *LiveViewer) Push(event MCPEvent) {
	b, err := json.Marshal(event)
	if err != nil {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	for ch := range v.clients {
		select {
		case ch <- b:
		default:
			// Slow/stuck client — drop the event rather than block the
			// attestation path. The DAG/audit log remains the source of truth.
		}
	}
}

func (v *LiveViewer) subscribe() chan []byte {
	ch := make(chan []byte, 64)
	v.mu.Lock()
	v.clients[ch] = true
	v.mu.Unlock()
	return ch
}

func (v *LiveViewer) unsubscribe(ch chan []byte) {
	v.mu.Lock()
	delete(v.clients, ch)
	v.mu.Unlock()
	close(ch)
}

// ListenAndServe binds the given loopback address (e.g. "127.0.0.1:8765")
// and serves the SSE feed at /events and a minimal live page at /.
// It refuses to bind any address that is not loopback.
func (v *LiveViewer) ListenAndServe(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("live_viewer: invalid addr %q: %w", addr, err)
	}
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return fmt.Errorf("live_viewer: refusing non-loopback bind address %q", addr)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/events", v.handleSSE)
	mux.HandleFunc("/", v.handleIndex)

	srv := &http.Server{Addr: addr, Handler: mux}
	return srv.ListenAndServe()
}

func (v *LiveViewer) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*") // loopback-only server; safe to allow any origin (incl. file://)
	w.WriteHeader(http.StatusOK)

	ch := v.subscribe()
	defer v.unsubscribe(ch)

	for {
		select {
		case <-r.Context().Done():
			return
		case b, open := <-ch:
			if !open {
				return
			}
			fmt.Fprintf(w, "data: %s\n\n", b)
			flusher.Flush()
		}
	}
}

func (v *LiveViewer) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	v.mu.Lock()
	page := v.graphPage
	v.mu.Unlock()

	if page != nil {
		w.Write(page) //nolint:errcheck
		return
	}
	fmt.Fprint(w, liveViewerHTML)
}

const liveViewerHTML = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Khepra Flight Recorder — Live Attestation</title>
<style>
  body { background:#0a0e14; color:#c5d1de; font-family: "SF Mono", Consolas, monospace; margin:0; padding:24px; }
  h1 { font-size:16px; color:#5ad1e6; letter-spacing:0.05em; margin-bottom:4px; }
  .sub { color:#5b6675; font-size:12px; margin-bottom:20px; }
  .row { display:flex; gap:12px; padding:8px 10px; border-bottom:1px solid #1b212c; font-size:13px; align-items:baseline; }
  .row:hover { background:#11161f; }
  .t { color:#5b6675; width:90px; flex-shrink:0; }
  .type { width:80px; flex-shrink:0; font-weight:600; }
  .type.attest { color:#5ad1e6; }
  .type.exec { color:#9ad65a; }
  .type.error { color:#e6615a; }
  .tool { color:#e9c46a; width:220px; flex-shrink:0; }
  .meta { color:#7d8a99; flex:1; overflow:hidden; text-overflow:ellipsis; }
  .ok { color:#9ad65a; }
  .bad { color:#e6615a; }
  #feed { max-height: 80vh; overflow-y:auto; }
</style>
</head>
<body>
<h1>KHEPRA FLIGHT RECORDER</h1>
<div class="sub">Live ML-DSA-65 attestation feed — loopback only, no network egress</div>
<div id="feed"></div>
<script>
const feed = document.getElementById('feed');
const es = new EventSource('/events');
es.onmessage = (msg) => {
  const ev = JSON.parse(msg.data);
  const row = document.createElement('div');
  row.className = 'row';
  const time = new Date(ev.timestamp).toLocaleTimeString();
  const statusClass = ev.success ? 'ok' : 'bad';
  const typeClass = ev.type === 'attest' ? 'attest' : (ev.type === 'error' ? 'error' : 'exec');
  let metaText = '';
  if (ev.dag_hash) metaText = 'dag=' + ev.dag_hash.slice(0, 16) + '…  agent=' + (ev.agent_id || '-');
  else if (ev.error_msg) metaText = ev.error_msg;
  else metaText = 'agent=' + (ev.agent_id || '-') + (ev.duration_ms ? '  ' + ev.duration_ms + 'ms' : '');
  row.innerHTML =
    '<span class="t">' + time + '</span>' +
    '<span class="type ' + typeClass + '">' + ev.type.toUpperCase() + '</span>' +
    '<span class="tool ' + statusClass + '">' + (ev.tool_name || '-') + '</span>' +
    '<span class="meta">' + metaText + '</span>';
  feed.prepend(row);
};
</script>
</body>
</html>`
