#!/usr/bin/env node
/**
 * fix-file-close.mjs
 * Wraps `defer f.Close()` after os.OpenFile/os.Create with WRITE flags 
 * in an explicit error-checking closure.
 * 
 * Only targets writable open calls (O_WRONLY, O_RDWR, Create) to avoid 
 * modifying read-only file closes where the error is less critical.
 */
import fs from 'fs';
import path from 'path';

const ROOT = 'C:\\Users\\intel\\blackbox\\PQC-Khepra-MCP';

const targetFiles = [
  'pkg/poam/export.go',
  'pkg/mcp/signed_audit_log.go',
  'pkg/emass/emass.go',
  'pkg/drbc/genesis.go',
  'pkg/sca/compliance.go',
  'pkg/sca/grype_adapter.go',
  'pkg/mcp/tools/pqc_stig_tool.go',
  'pkg/mcp/tools/discover_assets.go',
  'cmd/adinkhepra/cmd_llm.go',
  'cmd/adinkhepra/cmd_poam.go',
  'pkg/scorpion/scorpion.go',
  'pkg/stigs/loader.go',
  'pkg/connectors/ckl.go',
  'pkg/connectors/nessus.go',
  'pkg/connectors/xccdf.go',
  'pkg/intel/exploitdb.go',
  'pkg/flight/replay.go',
  'pkg/audit/collect.go',
  'pkg/compliance/nemoclaw_checks.go',
];

// Lines that indicate a writable file open just above the defer
const WRITE_OPEN_PATTERNS = [
  'O_WRONLY',
  'O_RDWR',
  'os.Create(',
  'os.OpenFile(',
];

const EXPLICIT_CLOSE = `\t// Explicit close with error capture to prevent silent data loss (Go WARNING close-check).
\tdefer func() {
\t\tif cerr := f.Close(); cerr != nil {
\t\t\tlog.Printf("[WARN] file close error: %v", cerr)
\t\t}
\t}()`;

let totalFiles = 0;

for (const relPath of targetFiles) {
  const filePath = path.join(ROOT, relPath);
  if (!fs.existsSync(filePath)) {
    console.log(`SKIP (not found): ${relPath}`);
    continue;
  }

  let content = fs.readFileSync(filePath, 'utf8');
  const original = content;
  const lines = content.split('\n');
  const newLines = [...lines];
  let modified = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    
    // Found a plain "defer f.Close()" (already wrapped ones are safe to skip)
    if (line === 'defer f.Close()' || line === 'defer rf.Close()') {
      // Check preceding ~5 lines for write-mode open
      const ctx = lines.slice(Math.max(0, i - 8), i).join('\n');
      const isWritable = WRITE_OPEN_PATTERNS.some(p => ctx.includes(p));
      const alreadyExplicit = lines[i].includes('func()');
      
      if (isWritable && !alreadyExplicit) {
        const varName = line.includes('rf.') ? 'rf' : 'f';
        const indent = lines[i].match(/^(\t*)/)[1];
        newLines[i] = `${indent}// Explicit close with error capture to prevent silent data loss (Go WARNING).\n${indent}defer func() {\n${indent}\tif cerr := ${varName}.Close(); cerr != nil {\n${indent}\t\tlog.Printf("[WARN] file close error: %v", cerr)\n${indent}\t}\n${indent}}()`;
        modified = true;
        console.log(`  fixed: ${relPath}:${i + 1} (${varName})`);
      }
    }
  }

  if (modified) {
    content = newLines.join('\n');
    fs.writeFileSync(filePath, content, 'utf8');
    totalFiles++;
  }
}

console.log(`\nDone: ${totalFiles} files updated`);
