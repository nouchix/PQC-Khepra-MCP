
with open("pkg/mcp/router.go", "r") as f:
    s = f.read()

# Imports
s = re.sub(r'"github\.com/nouchix/PQC-Khepra-MCP/pkg/attest"\n', '"github.com/nouchix/PQC-Khepra-MCP/pkg/mcp/kernelports"\n', s)
s = re.sub(r'"github\.com/nouchix/PQC-Khepra-MCP/pkg/flight"\n', '', s)
s = re.sub(r'\blicpkg "github\.com/nouchix/PQC-Khepra-MCP/pkg/license"\n', '', s)
s = re.sub(r'\bkhlog "github\.com/nouchix/PQC-Khepra-MCP/pkg/logging"\n', '', s)

# Types
s = s.replace('attest  *attest.DAGAttestor', 'attest  kernelports.Attestor')
s = s.replace('license *licpkg.KhepraLicense', 'license kernelports.LicenseChecker')
s = s.replace('recorder *flight.Recorder', 'recorder kernelports.FlightRecorder')

s = s.replace('Attestor       *attest.DAGAttestor', 'Attestor       kernelports.Attestor')
s = s.replace('License        *licpkg.KhepraLicense', 'License        kernelports.LicenseChecker')
s = s.replace('FlightRecorder *flight.Recorder', 'FlightRecorder kernelports.FlightRecorder')
s = s.replace('Logger         khlog.Logger', 'Logger         *log.Logger')

s = s.replace('logger:            cfg.Logger,', 'logger:            cfg.Logger,') # Just to be sure

# Usage
s = s.replace('cfg.Logger.WithField("component", "mcp-router")', 'cfg.Logger')
s = s.replace('r.logger.WithField', 'r.logger.Printf') # This will break if it was chained, let's fix it differently

s = re.sub(r'r\.logger\.WithField\([^)]+\)\.Printf', 'r.logger.Printf', s)
s = re.sub(r'r\.logger\.WithField\([^)]+\)\.Fatalf', 'r.logger.Fatalf', s)
s = re.sub(r'r\.logger\.WithField\([^)]+\)\.Errorf', 'r.logger.Printf', s)
s = re.sub(r'r\.logger\.WithField\([^)]+\)\.Info', 'r.logger.Println', s)
s = re.sub(r'r\.logger\.WithField\([^)]+\)\.Error', 'r.logger.Println', s)
s = re.sub(r'r\.logger\.WithField\([^)]+\)\.Warnf', 'r.logger.Printf', s)
s = re.sub(r'r\.logger\.WithField\([^)]+\)\.Debugf', 'r.logger.Printf', s)

s = s.replace('flight.OutcomeSuccess', '"success"')
s = s.replace('flight.OutcomeError', '"error"')
s = s.replace('flight.RiskClass(spec.RiskClass)', 'string(spec.RiskClass)')
s = s.replace('RiskClass:     spec.RiskClass', 'RiskClass:     string(spec.RiskClass)')

s = s.replace('licpkg.CheckToolAccess(r.license, call.ToolName)', 'r.license.Check(call.ToolName)')
s = s.replace('r.license != nil', 'r.license != nil') # This is fine

# Attestor / FlightRecorder
s = s.replace('signedEnv, err := r.attest.SignEnvelope(ctx, env)', 'signedEnvAny, err := r.attest.SignEnvelope(ctx, env)\n\t\tif err != nil { return nil, err }\n\t\tsignedEnv := signedEnvAny.(SecureEnvelope)')

# Recorder signature: recorder.Record(ctx context.Context, input kernelports.RecordInput)
s = s.replace('_, recErr := r.recorder.Record(', 'recErr := r.recorder.Record(ctx, ')

# Fix the Secret Scan Loop (which we already sliced out but since we did git checkout it's back)
block_str = '''		for _, sf := range runOutputSecretScan(outputBytes, call.ToolName) {
			r.logger.Printf("[MCP:SECRET-SCAN] tool=%q pattern=%q severity=%s owasp=%s (non-fatal)",
				call.ToolName, sf.title, sf.severity, sf.owaspTag)
			warnings = append(warnings, fmt.Sprintf("secret-scan [%s]: %s", sf.owaspTag, sf.title))
			r.events.Emit(MCPEvent{
				Type:    EventPolicy,
				Success: false,
				Metadata: map[string]any{
					"step":      "secret_scan",
					"tool":      call.ToolName,
					"agent":     id.AgentID,
					"owasp_tag": sf.owaspTag,
					"asi_tag":   sf.asiTag,
					"severity":  sf.severity,
					"pattern":   sf.title,
				},
			})
		}'''
s = s.replace(block_str, "")

with open("pkg/mcp/router.go", "w") as f:
    f.write(s)
