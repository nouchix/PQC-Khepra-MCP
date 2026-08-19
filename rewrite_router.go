package main

import (
	"io/ioutil"
	"strings"
	"regexp"
)

func main() {
	b, err := ioutil.ReadFile("pkg/mcp/router.go")
	if err != nil { panic(err) }
	
	s := string(b)
	
	s = strings.ReplaceAll(s, "\"github.com/nouchix/PQC-Khepra-MCP/pkg/flight\"", "\"github.com/nouchix/PQC-Khepra-MCP/pkg/mcp/kernelports\"")
	s = strings.ReplaceAll(s, "\"github.com/nouchix/PQC-Khepra-MCP/pkg/license\"\n", "")
	s = strings.ReplaceAll(s, "licpkg \"github.com/nouchix/PQC-Khepra-MCP/pkg/license\"\n", "")
	s = strings.ReplaceAll(s, "khlog \"github.com/nouchix/PQC-Khepra-MCP/pkg/logging\"\n", "")
	
	s = regexp.MustCompile(`(?s)// Attestor records tool.*?type Attestor interface \{.*?\n\}`).ReplaceAllString(s, "")
	
	s = strings.ReplaceAll(s, "attest   Attestor", "attest   kernelports.Attestor")
	s = strings.ReplaceAll(s, "license *licpkg.KhepraLicense", "licCheck kernelports.LicenseChecker")
	s = strings.ReplaceAll(s, "recorder *flight.Recorder", "recorder kernelports.FlightRecorder")
	
	s = strings.ReplaceAll(s, "Attestor Attestor", "Attestor kernelports.Attestor")
	s = strings.ReplaceAll(s, "License *licpkg.KhepraLicense", "License kernelports.LicenseChecker")
	s = strings.ReplaceAll(s, "FlightRecorder *flight.Recorder", "FlightRecorder kernelports.FlightRecorder")
	
	s = strings.ReplaceAll(s, "licCheck:          cfg.License,", "licCheck:          cfg.License,\n\t\trecorder:          cfg.FlightRecorder,")
	s = strings.ReplaceAll(s, "recorder:          cfg.FlightRecorder,", "recorder:          cfg.FlightRecorder,") // in case I doubled it up

	s = strings.ReplaceAll(s, "tierErr := licpkg.CheckToolAccess(r.license, call.ToolName)", "tierErr := r.licCheck.Allow(call.ToolName)")
	
	s = strings.ReplaceAll(s, "flight.RecordInput", "kernelports.RecordInput")
	s = strings.ReplaceAll(s, "flight.OutcomeError", "\"error\"")
	s = strings.ReplaceAll(s, "flight.OutcomeSuccess", "\"success\"")
	s = strings.ReplaceAll(s, "flight.BuildIntentSummary", "kernelports.BuildIntentSummary")
	s = strings.ReplaceAll(s, "string(spec.RiskClass)", "string(spec.RiskClass)")
	
	s = strings.ReplaceAll(s, "signedEnv, err := r.attest.SignEnvelope(ctx, env)", "signedEnvRaw, err := r.attest.SignEnvelope(ctx, env)\n\t\tif err != nil {\n\t\t\t// Log the failure, but return the unsigned result (fail-open for UX, fail-closed for audit).\n\t\t\tr.logger.Printf(\"[MCP:ATTEST] WARN: envelope signing failed for tool=%q: %v\", spec.Name, err)\n\t\t\treturn &MCPToolResponse{Result: env}, nil\n\t\t}\n\t\tsignedEnv, ok := signedEnvRaw.(SecureEnvelope)\n\t\tif !ok {\n\t\t\tr.logger.Printf(\"[MCP:ATTEST] WARN: envelope cast failed for tool=%q\", spec.Name)\n\t\t\treturn &MCPToolResponse{Result: env}, nil\n\t\t}")
	
	// Remove the original error check for SignEnvelope since we replaced it inline
	s = regexp.MustCompile(`signedEnv, ok := signedEnvRaw.\(SecureEnvelope\)\n.*?\n\t\treturn &MCPToolResponse\{Result: env\}, nil\n\t\}\n\n\t// Original err check that we need to remove:\n\tif err != nil \{\n\t\t// Log the failure.*?\n\t\treturn &MCPToolResponse\{Result: env\}, nil\n\t\}`).ReplaceAllString(s, "signedEnv, ok := signedEnvRaw.(SecureEnvelope)\n\t\tif !ok {\n\t\t\tr.logger.Printf(\"[MCP:ATTEST] WARN: envelope cast failed for tool=%q\", spec.Name)\n\t\t\treturn &MCPToolResponse{Result: env}, nil\n\t\t}")

	err = ioutil.WriteFile("pkg/mcp/router.go", []byte(s), 0644)
	if err != nil { panic(err) }
}
