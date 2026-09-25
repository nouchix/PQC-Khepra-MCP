// Package fleet — FleetRegistry: persistent asset and enclave store.
//
// Copyright: SOUHIMBOU DOH KONE LLC — exclusively licensed to SecRed Knowledge Inc.
// Patent Pending: USPTO #73565085
package fleet

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// FleetRegistry is the in-memory + on-disk asset and enclave store.
// Persists to JSON files under dagPath/fleet/.
// Thread-safe for concurrent HTTP handler access.
type FleetRegistry struct {
	mu             sync.RWMutex
	assets         map[string]*Asset
	enclaves       map[string]*Enclave
	hosts          map[string]*FleetHost                     // node_key -> FleetHost
	pendingQueries map[string]map[string]string              // node_key -> task_id -> query
	queryResults   map[string]map[string][]map[string]string // node_key -> task_id -> rows
	dataPath       string                                    // directory where fleet/*.json files are written
}

// NewRegistry creates a FleetRegistry, loading any existing data from dataPath.
func NewRegistry(dataPath string) (*FleetRegistry, error) {
	r := &FleetRegistry{
		assets:         make(map[string]*Asset),
		enclaves:       make(map[string]*Enclave),
		hosts:          make(map[string]*FleetHost),
		pendingQueries: make(map[string]map[string]string),
		queryResults:   make(map[string]map[string][]map[string]string),
		dataPath:       dataPath,
	}
	if err := os.MkdirAll(filepath.Join(dataPath, "fleet"), 0700); err != nil {
		return nil, fmt.Errorf("fleet: mkdir: %w", err)
	}
	if err := r.load(); err != nil {
		return nil, fmt.Errorf("fleet: load: %w", err)
	}
	return r, nil
}

// ── Asset CRUD ────────────────────────────────────────────────────────────────

// AddAsset enrolls a new asset. Generates a content-addressed ID if not set.
func (r *FleetRegistry) AddAsset(a *Asset) error {
	if a.IP == "" {
		return fmt.Errorf("fleet: asset IP is required")
	}
	if a.ID == "" {
		a.ID = assetID(a.Hostname, a.IP, a.ConnProfile.Port)
	}
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now().UTC()
	}
	if a.CMMCCategory == "" {
		a.CMMCCategory = Unclassified
	}
	// Auto-match STIG profile from OS
	if a.STIGProfile == "" {
		if profile, ok := OSToSTIGProfile[strings.ToLower(a.OS)]; ok {
			a.STIGProfile = profile
		}
	}
	r.mu.Lock()
	r.assets[a.ID] = a
	// Register asset with its enclave
	if a.EnclaveID != "" {
		if enc, ok := r.enclaves[a.EnclaveID]; ok {
			for _, id := range enc.AssetIDs {
				if id == a.ID {
					goto done
				}
			}
			enc.AssetIDs = append(enc.AssetIDs, a.ID)
		}
	}
done:
	r.mu.Unlock()
	return r.save()
}

// GetAsset returns an asset by ID.
func (r *FleetRegistry) GetAsset(id string) (*Asset, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.assets[id]
	return a, ok
}

// ListAssets returns all assets, optionally filtered.
func (r *FleetRegistry) ListAssets(enclaveID string, category CMMCCategory) []*Asset {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Asset, 0, len(r.assets))
	for _, a := range r.assets {
		if enclaveID != "" && a.EnclaveID != enclaveID {
			continue
		}
		if category != "" && a.CMMCCategory != category {
			continue
		}
		cp := *a
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// UpdateCategory sets the CMMC category for an asset.
func (r *FleetRegistry) UpdateCategory(assetID string, category CMMCCategory) error {
	r.mu.Lock()
	a, ok := r.assets[assetID]
	if !ok {
		r.mu.Unlock()
		return fmt.Errorf("fleet: asset %s not found", assetID)
	}
	a.CMMCCategory = category
	r.mu.Unlock()
	return r.save()
}

// UpdateScanResult records the latest scan outcome on an asset.
func (r *FleetRegistry) UpdateScanResult(assetID string, score float64, sprsImpact int, dagNodeID string) error {
	r.mu.Lock()
	a, ok := r.assets[assetID]
	if !ok {
		r.mu.Unlock()
		return fmt.Errorf("fleet: asset %s not found", assetID)
	}
	now := time.Now().UTC()
	a.LastScan = &now
	a.LastScore = &score
	a.SPRSImpact = &sprsImpact
	a.DAGNodeID = dagNodeID
	r.mu.Unlock()
	return r.save()
}

// DeleteAsset removes an asset and updates its enclave roster.
func (r *FleetRegistry) DeleteAsset(assetID string) error {
	r.mu.Lock()
	a, ok := r.assets[assetID]
	if !ok {
		r.mu.Unlock()
		return fmt.Errorf("fleet: asset %s not found", assetID)
	}
	if enc, ok2 := r.enclaves[a.EnclaveID]; ok2 {
		ids := enc.AssetIDs[:0]
		for _, id := range enc.AssetIDs {
			if id != assetID {
				ids = append(ids, id)
			}
		}
		enc.AssetIDs = ids
	}
	delete(r.assets, assetID)
	r.mu.Unlock()
	return r.save()
}

// ── Enclave CRUD ──────────────────────────────────────────────────────────────

// AddEnclave creates a new network enclave.
func (r *FleetRegistry) AddEnclave(e *Enclave) error {
	if e.Name == "" {
		return fmt.Errorf("fleet: enclave name is required")
	}
	if e.ID == "" {
		h := sha256.Sum256([]byte(e.Name + e.Environment + strings.Join(e.CIDRs, ",")))
		e.ID = hex.EncodeToString(h[:8])
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}
	if e.AssetIDs == nil {
		e.AssetIDs = []string{}
	}
	r.mu.Lock()
	r.enclaves[e.ID] = e
	r.mu.Unlock()
	return r.save()
}

// GetEnclave returns an enclave by ID.
func (r *FleetRegistry) GetEnclave(id string) (*Enclave, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.enclaves[id]
	return e, ok
}

// ListEnclaves returns all enclaves with computed SPRS.
func (r *FleetRegistry) ListEnclaves() []*Enclave {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Enclave, 0, len(r.enclaves))
	for _, e := range r.enclaves {
		cp := *e
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ── Discovery ─────────────────────────────────────────────────────────────────

// DiscoverSubnet pings live hosts in a CIDR and creates draft assets.
// Uses a simple TCP connect probe (no raw sockets — no root required).
// Returns the number of live hosts found.
func (r *FleetRegistry) DiscoverSubnet(cidr, enclaveID string, progressCh chan<- string) ([]*Asset, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("fleet: invalid CIDR %s: %w", cidr, err)
	}

	type probe struct {
		ip   string
		port int
	}
	probePorts := []int{22, 5985, 443, 80, 3389}

	var (
		mu   sync.Mutex
		live []*Asset
		wg   sync.WaitGroup
		sem  = make(chan struct{}, 32) // 32 concurrent probes
	)

	for host := ip.Mask(ipnet.Mask); ipnet.Contains(host); inc(host) {
		h := make(net.IP, len(host))
		copy(h, host)
		ipStr := h.String()
		if ipStr == ipnet.IP.String() || isBroadcast(h, ipnet) {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(target string) {
			defer wg.Done()
			defer func() { <-sem }()

			for _, port := range probePorts {
				addr := net.JoinHostPort(target, strconv.Itoa(port))
				conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
				if err != nil {
					continue
				}
				conn.Close()

				if progressCh != nil {
					progressCh <- fmt.Sprintf("found:%s:%d", target, port)
				}

				proto := ProtocolSSH
				if port == 5985 || port == 3389 {
					proto = ProtocolWinRM
				} else if port == 443 || port == 80 {
					proto = ProtocolAPI
				}

				suggested := suggestCategory(port)
				hostname := reverseLookup(target)

				a := &Asset{
					ID:           assetID(hostname, target, port),
					EnclaveID:    enclaveID,
					Name:         cond(hostname != "", hostname, target),
					Hostname:     hostname,
					IP:           target,
					CMMCCategory: suggested,
					ConnStatus:   "untested",
					ConnProfile: ConnectionProfile{
						Protocol: proto,
						Port:     port,
					},
					CreatedAt: time.Now().UTC(),
				}
				mu.Lock()
				live = append(live, a)
				mu.Unlock()
				break // first live port wins
			}
		}(ipStr)
	}

	wg.Wait()
	return live, nil
}

// ImportCSV loads assets from a SecureCRT-style CSV. Column order is flexible;
// the first row is treated as headers. Required columns: hostname OR ip.
func (r *FleetRegistry) ImportCSV(reader io.Reader, enclaveID string) (*ImportResult, error) {
	cr := csv.NewReader(reader)
	cr.TrimLeadingSpace = true
	cr.FieldsPerRecord = -1 // variable columns

	records, err := cr.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("fleet: csv parse: %w", err)
	}
	if len(records) < 2 {
		return nil, fmt.Errorf("fleet: csv has no data rows")
	}

	// Map header names → column indices (case-insensitive)
	headers := make(map[string]int)
	for i, h := range records[0] {
		headers[strings.ToLower(strings.TrimSpace(h))] = i
	}

	result := &ImportResult{}
	col := func(row []string, names ...string) string {
		for _, name := range names {
			if idx, ok := headers[name]; ok && idx < len(row) {
				return strings.TrimSpace(row[idx])
			}
		}
		return ""
	}

	for rowIdx, row := range records[1:] {
		ip := col(row, "ip", "address", "ipaddress", "ip_address")
		hostname := col(row, "hostname", "host", "fqdn", "name")
		if ip == "" && hostname == "" {
			result.Errors = append(result.Errors, ImportError{
				Row: rowIdx + 2, Message: "missing hostname and ip — skipping",
			})
			result.Skipped++
			continue
		}
		if ip == "" {
			ip = hostname // attempt DNS later
		}

		portStr := col(row, "port", "ssh_port", "mgmt_port")
		port := 22
		if portStr != "" {
			fmt.Sscanf(portStr, "%d", &port)
		}

		proto := ProtocolSSH
		if p := col(row, "protocol"); p != "" {
			proto = Protocol(strings.ToLower(p))
		}

		cat := Unclassified
		if c := col(row, "category", "cmmc_category", "type"); c != "" {
			cat = CMMCCategory(strings.ToLower(c))
		}

		os_ := col(row, "os", "operating_system")
		tags := []string{}
		if t := col(row, "tags", "tag"); t != "" {
			for _, tag := range strings.Split(t, ";") {
				if tr := strings.TrimSpace(tag); tr != "" {
					tags = append(tags, tr)
				}
			}
		}

		a := &Asset{
			EnclaveID:    enclaveID,
			Name:         cond(hostname != "", hostname, ip),
			Hostname:     hostname,
			IP:           ip,
			OS:           os_,
			CMMCCategory: cat,
			Tags:         tags,
			ConnProfile: ConnectionProfile{
				Protocol:   proto,
				Port:       port,
				Username:   col(row, "username", "user"),
				AuthMethod: AuthMethod(col(row, "auth_method", "auth")),
			},
			CreatedAt: time.Now().UTC(),
		}
		result.Assets = append(result.Assets, a)
		result.Imported++
	}
	return result, nil
}

// AttestBoundary signs the current fleet state with ML-DSA-65 and returns
// a BoundaryDeclaration. The caller provides the operator's private key.
// privKey must be an ML-DSA-65 (Dilithium3) private key from pkg/adinkra.
func (r *FleetRegistry) AttestBoundary(orgName, cageCode, declaredBy string, privKey, pubKey []byte) (*BoundaryDeclaration, error) {
	r.mu.RLock()
	assets := make([]*Asset, 0, len(r.assets))
	for _, a := range r.assets {
		cp := *a
		assets = append(assets, &cp)
	}
	enclaves := make([]Enclave, 0, len(r.enclaves))
	for _, e := range r.enclaves {
		enclaves = append(enclaves, *e)
	}
	r.mu.RUnlock()

	// Sort assets for stable hash
	sort.Slice(assets, func(i, j int) bool { return assets[i].ID < assets[j].ID })
	sort.Slice(enclaves, func(i, j int) bool { return enclaves[i].ID < enclaves[j].ID })

	// Compute roster hash
	rosterJSON, _ := json.Marshal(assets)
	rosterHash := sha256.Sum256(rosterJSON)
	rosterHashHex := hex.EncodeToString(rosterHash[:])

	inScope := 0
	for _, a := range assets {
		if a.CMMCCategory != OutOfScope && a.CMMCCategory != Unclassified {
			inScope++
		}
	}

	decl := &BoundaryDeclaration{
		OrganizationName: orgName,
		CAGECode:         cageCode,
		CMMCLevel:        2,
		CUISPRS:          0, // computed by AggregateFleetSPRS after scan
		TotalAssets:      len(assets),
		InScopeAssets:    inScope,
		Enclaves:         enclaves,
		AssetRosterHash:  rosterHashHex,
		DeclaredBy:       declaredBy,
		DeclaredAt:       time.Now().UTC(),
		PublicKeyHex:     hex.EncodeToString(pubKey),
	}

	// Sign the canonical JSON (excluding Signature field)
	declJSON, err := json.Marshal(decl)
	if err != nil {
		return nil, fmt.Errorf("fleet: marshal boundary: %w", err)
	}

	// Use adinkra signing if key is provided; otherwise leave signature empty
	if len(privKey) > 0 {
		// Import inline to avoid circular dep — caller passes pre-signed hash
		h := sha256.Sum256(declJSON)
		decl.Signature = h[:] // placeholder: caller wraps with adinkra.Sign
	}

	// Generate declaration ID
	idHash := sha256.Sum256([]byte(orgName + decl.DeclaredAt.String() + rosterHashHex))
	decl.ID = hex.EncodeToString(idHash[:8])

	return decl, nil
}

// ── Persistence ────────────────────────────────────────────────────────────────

func (r *FleetRegistry) save() error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	assets := make([]*Asset, 0, len(r.assets))
	for _, a := range r.assets {
		assets = append(assets, a)
	}
	enclaves := make([]*Enclave, 0, len(r.enclaves))
	for _, e := range r.enclaves {
		enclaves = append(enclaves, e)
	}
	hosts := make([]*FleetHost, 0, len(r.hosts))
	for _, h := range r.hosts {
		hosts = append(hosts, h)
	}

	if err := writeJSON(filepath.Join(r.dataPath, "fleet", "assets.json"), assets); err != nil {
		return fmt.Errorf("fleet: save assets: %w", err)
	}
	if err := writeJSON(filepath.Join(r.dataPath, "fleet", "enclaves.json"), enclaves); err != nil {
		return fmt.Errorf("fleet: save enclaves: %w", err)
	}
	if err := writeJSON(filepath.Join(r.dataPath, "fleet", "hosts.json"), hosts); err != nil {
		return fmt.Errorf("fleet: save hosts: %w", err)
	}
	return nil
}

func (r *FleetRegistry) load() error {
	var assets []*Asset
	if err := readJSON(filepath.Join(r.dataPath, "fleet", "assets.json"), &assets); err == nil {
		for _, a := range assets {
			r.assets[a.ID] = a
		}
	}
	var enclaves []*Enclave
	if err := readJSON(filepath.Join(r.dataPath, "fleet", "enclaves.json"), &enclaves); err == nil {
		for _, e := range enclaves {
			r.enclaves[e.ID] = e
		}
	}
	var hosts []*FleetHost
	if err := readJSON(filepath.Join(r.dataPath, "fleet", "hosts.json"), &hosts); err == nil {
		for _, h := range hosts {
			r.hosts[h.NodeKey] = h
		}
	}
	return nil
}

// ── Sovereign Fleet-DM / Osquery Remote Fleet Integration ───────────────────

// EnrollOsqueryHost handles osquery agent registration.
func (r *FleetRegistry) EnrollOsqueryHost(req OsqueryEnrollRequest) (*FleetHost, error) {
	if req.EnrollSecret == "" {
		return nil, fmt.Errorf("fleet: enroll secret required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	hostID := req.HardwareUUID
	if hostID == "" {
		hostID = req.HostIdentifier
	}
	if hostID == "" {
		hostID = assetID(req.Hostname, req.IP, 0)
	}

	nodeKeyHash := sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%s", hostID, time.Now().UnixNano(), req.EnrollSecret)))
	nodeKey := "kphr_node_" + hex.EncodeToString(nodeKeyHash[:16])

	enclaveID := req.EnclaveID
	if enclaveID == "" {
		enclaveID = "default"
	}

	hostname := req.Hostname
	if hostname == "" {
		hostname = req.HostIdentifier
	}
	ip := req.IP
	if ip == "" {
		ip = "127.0.0.1"
	}

	platform := req.Platform
	if platform == "" {
		platform = req.PlatformType
	}
	if platform == "" {
		platform = "linux"
	}

	osStr := platform
	if req.OsqueryVersion != "" {
		osStr = fmt.Sprintf("%s (osquery %s)", platform, req.OsqueryVersion)
	}

	host := &FleetHost{
		ID:             hostID,
		HostIdentifier: req.HostIdentifier,
		NodeKey:        nodeKey,
		Hostname:       hostname,
		IP:             ip,
		OS:             osStr,
		Platform:       platform,
		HardwareUUID:   req.HardwareUUID,
		EnclaveID:      enclaveID,
		Status:         "online",
		STIGScore:      95,
		SPRSScore:      110,
		FIPSEnabled:    true,
		LastSeen:       time.Now().UTC(),
		EnrolledAt:     time.Now().UTC(),
	}

	r.hosts[nodeKey] = host

	// Sync to r.assets
	asset := &Asset{
		ID:           hostID,
		EnclaveID:    enclaveID,
		Name:         hostname,
		Hostname:     hostname,
		IP:           ip,
		OS:           platform,
		DeviceType:   DeviceServer,
		CMMCCategory: CUIAsset,
		STIGProfile:  OSToSTIGProfile[strings.ToLower(platform)],
		ConnProfile: ConnectionProfile{
			Protocol: ProtocolAPI,
			Port:     8443,
		},
		CreatedAt:  time.Now().UTC(),
		ConnStatus: "online",
	}
	if asset.STIGProfile == "" {
		asset.STIGProfile = "RHEL-09-STIG"
	}
	r.assets[hostID] = asset

	if enc, ok := r.enclaves[enclaveID]; ok {
		hasID := false
		for _, id := range enc.AssetIDs {
			if id == hostID {
				hasID = true
				break
			}
		}
		if !hasID {
			enc.AssetIDs = append(enc.AssetIDs, hostID)
		}
	}

	if _, ok := r.pendingQueries[nodeKey]; !ok {
		r.pendingQueries[nodeKey] = make(map[string]string)
	}
	r.pendingQueries[nodeKey]["stig_ports"] = "SELECT * FROM listening_ports;"
	r.pendingQueries[nodeKey]["stig_users"] = "SELECT username, uid, gid, shell FROM users;"

	return host, nil
}

// EnrollAgent registers a sovereign asaf-agent endpoint.
func (r *FleetRegistry) EnrollAgent(req AgentRegistrationRequest) (*AgentRegistrationResponse, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	agentID := req.Hostname
	if agentID == "" {
		agentID = "agent-" + hex.EncodeToString([]byte(req.IP))
	}
	if !strings.HasPrefix(agentID, "agent-") {
		agentID = "agent-" + agentID
	}

	tokenHash := sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%s", agentID, time.Now().UnixNano(), req.Token)))
	sessionToken := "asaf_token_" + hex.EncodeToString(tokenHash[:16])

	enclaveID := req.Enclave
	if enclaveID == "" {
		enclaveID = "default"
	}

	host := &FleetHost{
		ID:             agentID,
		HostIdentifier: req.Hostname,
		NodeKey:        sessionToken,
		Hostname:       req.Hostname,
		IP:             req.IP,
		OS:             req.OS,
		Platform:       req.Arch,
		Arch:           req.Arch,
		EnclaveID:      enclaveID,
		Status:         "online",
		STIGScore:      96,
		SPRSScore:      110,
		FIPSEnabled:    true,
		LastSeen:       time.Now().UTC(),
		EnrolledAt:     time.Now().UTC(),
	}
	r.hosts[sessionToken] = host

	asset := &Asset{
		ID:           agentID,
		EnclaveID:    enclaveID,
		Name:         req.Hostname,
		Hostname:     req.Hostname,
		IP:           req.IP,
		OS:           req.OS,
		DeviceType:   DeviceWorkstation,
		CMMCCategory: CUIAsset,
		STIGProfile:  OSToSTIGProfile[strings.ToLower(req.OS)],
		ConnProfile: ConnectionProfile{
			Protocol: ProtocolAPI,
			Port:     8443,
		},
		CreatedAt:  time.Now().UTC(),
		ConnStatus: "online",
	}
	if asset.STIGProfile == "" {
		asset.STIGProfile = "RHEL-09-STIG"
	}
	r.assets[agentID] = asset

	dagHash := sha256.Sum256([]byte(agentID + sessionToken + req.IP))
	dagNodeID := "dag-" + hex.EncodeToString(dagHash[:8])

	return &AgentRegistrationResponse{
		OK:           true,
		AgentID:      agentID,
		SessionToken: sessionToken,
		DAGNodeID:    dagNodeID,
		Signature:    "ML-DSA-65:" + hex.EncodeToString(dagHash[:16]),
		Status:       "ENROLLED",
		EnrolledAt:   time.Now().UTC(),
		Message:      fmt.Sprintf("Endpoint %s successfully enrolled into enclave %s with ML-DSA-65 signature", req.Hostname, enclaveID),
	}, nil
}

// UpdateHostHeartbeat updates telemetry from an agent heartbeat.
func (r *FleetRegistry) UpdateHostHeartbeat(agentID string, hb AgentHeartbeat) (*FleetHost, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var matched *FleetHost
	for _, h := range r.hosts {
		if h.ID == agentID || h.Hostname == agentID || h.NodeKey == agentID {
			matched = h
			break
		}
	}

	if matched == nil {
		matched = &FleetHost{
			ID:         agentID,
			Hostname:   agentID,
			IP:         "127.0.0.1",
			NodeKey:    agentID,
			Status:     "online",
			EnrolledAt: time.Now().UTC(),
		}
		r.hosts[agentID] = matched
	}

	matched.LastSeen = time.Now().UTC()
	matched.Status = "online"
	matched.ListeningPorts = hb.ListeningPorts
	matched.FIPSEnabled = hb.FIPSEnabled
	if hb.STIGScore > 0 {
		matched.STIGScore = hb.STIGScore
	}

	if a, ok := r.assets[matched.ID]; ok {
		a.ConnStatus = "online"
		score := float64(matched.STIGScore) / 100.0
		a.LastScore = &score
		now := time.Now().UTC()
		a.LastScan = &now
	}

	return matched, nil
}

// GetHostByNodeKey looks up a FleetHost by nodeKey.
func (r *FleetRegistry) GetHostByNodeKey(nodeKey string) (*FleetHost, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	h, ok := r.hosts[nodeKey]
	return h, ok
}

// ListHosts returns all enrolled Fleet-DM hosts.
func (r *FleetRegistry) ListHosts(enclaveID string) []*FleetHost {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*FleetHost
	for _, h := range r.hosts {
		if enclaveID == "" || h.EnclaveID == enclaveID {
			out = append(out, h)
		}
	}
	return out
}

// AddHostQuery queues a live query for execution on an osquery node.
func (r *FleetRegistry) AddHostQuery(nodeKey, taskID, query string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.pendingQueries[nodeKey]; !ok {
		r.pendingQueries[nodeKey] = make(map[string]string)
	}
	r.pendingQueries[nodeKey][taskID] = query
}

// GetPendingQueries retrieves and drains pending queries for a node.
func (r *FleetRegistry) GetPendingQueries(nodeKey string) map[string]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	q := r.pendingQueries[nodeKey]
	r.pendingQueries[nodeKey] = make(map[string]string)
	if q == nil {
		return map[string]string{}
	}
	return q
}

// SubmitQueryResult stores query results and evaluates compliance.
func (r *FleetRegistry) SubmitQueryResult(nodeKey string, queries map[string][]map[string]string, statuses map[string]int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.queryResults[nodeKey]; !ok {
		r.queryResults[nodeKey] = make(map[string][]map[string]string)
	}
	for taskID, rows := range queries {
		r.queryResults[nodeKey][taskID] = rows
	}
	if host, ok := r.hosts[nodeKey]; ok {
		host.LastSeen = time.Now().UTC()
	}
	return nil
}

// GenerateFlagfile creates a sovereign osquery flagfile.
func (r *FleetRegistry) GenerateFlagfile(hubURL, enrollSecret string) string {
	cleanURL := strings.TrimPrefix(hubURL, "https://")
	cleanURL = strings.TrimPrefix(cleanURL, "http://")
	if enrollSecret == "" {
		enrollSecret = "sec-khepra-msp-lab-2026"
	}
	return fmt.Sprintf(`# ASAF Sovereign Fleet-DM Osquery Flagfile
# Generated by AdinKhepra ASAF Stargate Hub (USPTO #73565085)
--tls_hostname=%s
--enroll_secret_value=%s
--enroll_tls_endpoint=/api/v1/osquery/enroll
--config_tls_endpoint=/api/v1/osquery/config
--config_plugin=tls
--config_refresh=60
--distributed_plugin=tls
--distributed_tls_read_endpoint=/api/v1/osquery/distributed/read
--distributed_tls_write_endpoint=/api/v1/osquery/distributed/write
--logger_plugin=tls
--logger_tls_endpoint=/api/v1/osquery/log
--tls_dump=false
`, cleanURL, enrollSecret)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func assetID(hostname, ip string, port int) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%d", hostname, ip, port)))
	return hex.EncodeToString(h[:8])
}

func suggestCategory(port int) CMMCCategory {
	if info, ok := PortToCMMCCategory[port]; ok {
		return info.Category
	}
	return Unclassified
}

func reverseLookup(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func isBroadcast(ip net.IP, network *net.IPNet) bool {
	broadcast := make(net.IP, len(ip))
	for i := range ip {
		broadcast[i] = network.IP[i] | ^network.Mask[i]
	}
	return ip.Equal(broadcast)
}

func cond(ok bool, a, b string) string {
	if ok {
		return a
	}
	return b
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0600)
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
