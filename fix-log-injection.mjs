#!/usr/bin/env node
/**
 * fix-log-injection.mjs
 * 
 * Adds sanitizeLog() helper to target Go files and wraps user-controlled
 * values in log.Printf() calls to prevent log injection (CWE-117).
 * 
 * Strategy:
 * 1. For each target file, add sanitizeLog helper if not present
 * 2. Wrap string arguments in log.Printf that could be user-controlled
 *    using heuristic: wrap %s format args that are variable references
 *    (not string literals starting with "[")
 */

import fs from 'fs';
import path from 'path';

const ROOT = 'C:\\Users\\intel\\blackbox\\PQC-Khepra-MCP';

// The sanitizeLog helper to inject into each package (one per package)
const SANITIZE_HELPER = `
// sanitizeLog removes newline characters from user-controlled strings before
// logging to prevent log injection attacks (CWE-117 / CodeQL go/log-injection).
func sanitizeLog(s string) string {
\treturn strings.Map(func(r rune) rune {
\t\tif r == '\\n' || r == '\\r' || r == '\\t' {
\t\t\treturn ' '
\t\t}
\t\treturn r
\t}, s)
}
`;

// Files to process and the packages they belong to
const targetFiles = [
  // pkg/mcp
  'pkg/mcp/router.go',
  'pkg/mcp/executor.go',
  'pkg/mcp/sandbox.go',
  // pkg/gateway
  'pkg/gateway/layer4_control.go',
  'pkg/gateway/layer2_auth.go',
  'pkg/gateway/layer1_firewall.go',
  'pkg/gateway/stig_connector.go',
  // pkg/sekhem
  'pkg/sekhem/waf.go',
  // pkg/agi
  'pkg/agi/engine.go',
  // pkg/ouroboros
  'pkg/ouroboros/cycle.go',
  'pkg/ouroboros/khopesh.go',
  // pkg/ironbank
  'pkg/ironbank/transport.go',
  // pkg/webui
  'pkg/webui/dag_viewer.go',
  // cmd
  'cmd/webhook/main.go',
  'cmd/khepra-mcp/main.go',
  'cmd/khepra-daemon/main.go',
  'cmd/telemetry-server/main.go',
];

// Track which packages already have the helper
const processedPackages = new Set();

let totalFilesModified = 0;
let totalWraps = 0;

for (const relPath of targetFiles) {
  const filePath = path.join(ROOT, relPath);
  
  if (!fs.existsSync(filePath)) {
    console.log(`SKIP (not found): ${relPath}`);
    continue;
  }
  
  let content = fs.readFileSync(filePath, 'utf8');
  const original = content;
  
  // Extract package name
  const pkgMatch = content.match(/^package\s+(\w+)/m);
  if (!pkgMatch) {
    console.log(`SKIP (no package): ${relPath}`);
    continue;
  }
  const pkg = pkgMatch[1];
  
  // 1. Ensure strings is imported
  if (!content.includes('"strings"')) {
    // Add strings to import block
    content = content.replace(
      /^import \(/m,
      'import (\n\t"strings"'
    );
    // If no import block, this won't work — but all our files have one
  }
  
  // 2. Add sanitizeLog helper if not already present in this file/package
  // We add it to the first file we process for each package
  const pkgKey = path.dirname(relPath);
  if (!processedPackages.has(pkgKey) && !content.includes('func sanitizeLog(')) {
    // Add before the last closing brace or at end of file
    content = content.trimEnd() + '\n' + SANITIZE_HELPER;
    processedPackages.add(pkgKey);
    console.log(`  + Added sanitizeLog to ${relPath}`);
  }
  
  // 3. Wrap user-controlled log arguments
  // Pattern: log.Printf("...", var1, var2, ...) 
  // We wrap string variables that appear in format-string positions for %s
  // Heuristic: any identifier after a comma that's not a number/boolean/format-string
  let wrapCount = 0;
  
  // Replace log.Printf calls that contain user-controlled identifiers
  // We target specific patterns from the CodeQL alerts
  const logPatterns = [
    // Log calls with identifiers that are user-controlled
    // Pattern: log.Printf("...", something) where something is an identifier
    {
      // Match log.Printf lines with string format args
      // Wrap identifiers that come from user input heuristically
      regex: /\blog\.Printf\(([^)]+)\)/g,
      process: (match, args) => {
        // Find %s positions and wrap corresponding args
        const parts = splitArgs(args);
        if (parts.length < 2) return match;
        
        const fmt = parts[0];
        const fmtStr = fmt.trim();
        
        // Count %s in format string to know which args to wrap
        const sCount = (fmtStr.match(/%s/g) || []).length;
        if (sCount === 0) return match; // no string args
        
        let modified = false;
        let argIdx = 1; // skip format string
        let sIdx = 0;
        
        const newParts = [parts[0]];
        for (let i = 1; i < parts.length; i++) {
          const arg = parts[i].trim();
          const fmtChar = getFmtCharAt(fmtStr, i - 1);
          
          if (fmtChar === 's' && shouldWrap(arg)) {
            newParts.push(` sanitizeLog(${arg})`);
            modified = true;
            wrapCount++;
          } else {
            newParts.push(parts[i]);
          }
        }
        
        if (modified) {
          return `log.Printf(${newParts.join(',')})`;
        }
        return match;
      }
    }
  ];
  
  // Simpler targeted approach: wrap specific variable names that CodeQL flagged
  // Based on the alerts: ToolName, AgentID, remoteAddr, rlErr.Message, etc.
  const userControlledPatterns = [
    // MCP router patterns
    /log\.Printf\("(\[MCP:[^\]]+\] [^"]+)", ([^)]+)\)/g,
    // Gateway patterns  
    /log\.Printf\("(\[(?:AUTH|CONTROL|FIREWALL|LAYER[0-9])[^\]]*\] [^"]+)", ([^)]+)\)/g,
    // General patterns
    /\blog\.Printf\(([^)]+?(?:call\.ToolName|id\.AgentID|remoteAddr|err\.Error\(\)|event\.ID|identityID|limiter\.IdentityID)[^)]*?)\)/g,
  ];
  
  // Most targeted: wrap the specific identifiers that CodeQL flags
  // These are the variables that CodeQL traces as user-controlled
  const userControlledVars = [
    'call.ToolName', 'id.AgentID', 'remoteAddr', 'identityID',
    'limiter.IdentityID', 'event.ID', 'event.Type',
    'sub.CustomerEmail', 'sub.ID',
    'r.URL.Path', 'r.Method',
    'tool', 'agent', 'token',
  ];
  
  // Use line-by-line approach for safety
  const lines = content.split('\n');
  const newLines = lines.map(line => {
    // Only process log.Printf lines
    if (!line.includes('log.Printf(') && !line.includes('r.logger.Printf(')) {
      return line;
    }
    
    let newLine = line;
    for (const varName of userControlledVars) {
      // Only wrap if not already wrapped
      const alreadyWrapped = newLine.includes(`sanitizeLog(${varName})`);
      if (!alreadyWrapped && newLine.includes(varName)) {
        // Make sure it's in a log.Printf argument position (after a comma or opening paren before %s)
        // Simple heuristic: replace ", varName" with ", sanitizeLog(varName)"
        // and "(varName)" with "(sanitizeLog(varName))"
        const escapedVar = varName.replace('.', '\\.');
        newLine = newLine.replace(
          new RegExp(`(?<!sanitizeLog\\()\\b${escapedVar}\\b`, 'g'),
          `sanitizeLog(${varName})`
        );
        if (newLine !== line) wrapCount++;
      }
    }
    return newLine;
  });
  
  content = newLines.join('\n');
  
  if (content !== original) {
    fs.writeFileSync(filePath, content, 'utf8');
    totalFilesModified++;
    console.log(`MODIFIED: ${relPath} (${wrapCount} wraps)`);
    totalWraps += wrapCount;
  } else {
    console.log(`UNCHANGED: ${relPath}`);
  }
}

console.log(`\nDone: ${totalFilesModified} files modified, ~${totalWraps} log args wrapped`);

// Helper: split function call args respecting nested parens
function splitArgs(argsStr) {
  const parts = [];
  let depth = 0;
  let current = '';
  
  for (const ch of argsStr) {
    if (ch === '(' || ch === '[' || ch === '{') depth++;
    else if (ch === ')' || ch === ']' || ch === '}') depth--;
    
    if (ch === ',' && depth === 0) {
      parts.push(current);
      current = '';
    } else {
      current += ch;
    }
  }
  if (current) parts.push(current);
  return parts;
}

// Helper: check if arg should be wrapped (is a user-controlled identifier)
function shouldWrap(arg) {
  // Don't wrap: string literals, numbers, booleans, error.Error(), time values
  if (arg.startsWith('"') || arg.startsWith('`')) return false;
  if (/^\d/.test(arg)) return false;
  if (arg === 'true' || arg === 'false') return false;
  if (arg.includes('.Error()')) return false;
  if (arg.includes('time.Since') || arg.includes('time.Now')) return false;
  if (arg.includes('len(') || arg.includes('float64(')) return false;
  if (arg.startsWith('sanitizeLog(')) return false;
  return true;
}

// Helper: get format character at position i
function getFmtCharAt(fmtStr, argIdx) {
  const matches = [...fmtStr.matchAll(/%([a-zA-Z])/g)];
  if (argIdx < matches.length) return matches[argIdx][1];
  return '';
}
