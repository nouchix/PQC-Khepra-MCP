import re

files_to_update = {
    "pkg/mcp/server.go": (r'HardenedServerVersion = "1\.0\.0"', 'HardenedServerVersion = "2.0.0"'),
    "pkg/mcp/legacy/server.go": (r'cfg\.ServerVersion = "1\.0\.0"', 'cfg.ServerVersion = "2.0.0"'),
    "cmd/khepra-reporter/main.go": (r'reporterVersion\s*=\s*"1\.0\.0"', 'reporterVersion          = "2.0.0"'),
    "cmd/khepra-daemon/main.go": (r'"version":\s*"1\.0\.0"', '"version":  "2.0.0"'),
    "Makefile": (r'gen_manifest\.go "v1\.0\.0"', 'gen_manifest.go "v2.0.0"'),
    "Dockerfile.ironbank": (r'ARG VERSION=1\.0\.0', 'ARG VERSION=2.0.0'),
    "manifest.json": (r'"version": "1\.0\.0"', '"version": "2.0.0"'),
    "cmd/manifest-gen/main.go": (r'Version:\s*"1\.0\.0",', 'Version:       "2.0.0",')
}

for filepath, (pattern, replacement) in files_to_update.items():
    try:
        with open(filepath, "r") as f:
            content = f.read()
        
        # Replace the specific pattern
        new_content = re.sub(pattern, replacement, content)
        
        with open(filepath, "w") as f:
            f.write(new_content)
        print(f"Updated {filepath}")
    except Exception as e:
        print(f"Error updating {filepath}: {e}")

