import * as vscode from 'vscode';

const PROVIDER_ID = 'khepra.mcpProvider';
const SERVER_LABEL = 'KHEPRA Compliance Server';
const DOCKER_IMAGE = 'ghcr.io/nouchix/pqc-khepra-mcp:latest';

function buildServerDefinition(): vscode.McpStdioServerDefinition {
  const config = vscode.workspace.getConfiguration('khepra');
  const mode = config.get<string>('mode', 'sovereign');
  const transport = config.get<string>('transport', 'docker');
  const binaryPath = config.get<string>('binaryPath', '');
  const licenseKey = config.get<string>('licenseKey', '');

  const env: Record<string, string> = { KHEPRA_MODE: mode };
  if (licenseKey) {
    env.KHEPRA_LICENSE_KEY = licenseKey;
  }

  if (transport === 'binary' && binaryPath) {
    return new vscode.McpStdioServerDefinition(SERVER_LABEL, binaryPath, [], env);
  }

  const args = ['run', '--rm', '-i', '-e', `KHEPRA_MODE=${mode}`];
  if (licenseKey) {
    args.push('-e', 'KHEPRA_LICENSE_KEY');
  }
  args.push(DOCKER_IMAGE);
  return new vscode.McpStdioServerDefinition(SERVER_LABEL, 'docker', args, env);
}

export function activate(context: vscode.ExtensionContext): void {
  const didChange = new vscode.EventEmitter<void>();

  const provider: vscode.McpServerDefinitionProvider = {
    onDidChangeMcpServerDefinitions: didChange.event,
    provideMcpServerDefinitions: async () => [buildServerDefinition()],
    resolveMcpServerDefinition: async (definition) => definition
  };

  context.subscriptions.push(
    vscode.lm.registerMcpServerDefinitionProvider(PROVIDER_ID, provider),
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration('khepra')) {
        didChange.fire();
      }
    }),
    vscode.commands.registerCommand('khepra.openWhitepaper', () => {
      vscode.env.openExternal(
        vscode.Uri.parse('https://github.com/nouchix/PQC-Khepra-MCP/blob/main/Whitepaper.md')
      );
    })
  );
}

export function deactivate(): void {}
