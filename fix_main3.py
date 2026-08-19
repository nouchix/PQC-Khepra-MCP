
with open("cmd/khepra-mcp/main.go", "r") as f:
    s = f.read()

s = s.replace('srv.Serve(ctx)', 'srv.Run(ctx)')
s = s.replace('transport := khepramcp.NewStdioTransport(router, logger)', '')
s = s.replace('if err := transport.Start(ctx); err != nil {\n\t\tlogger.Fatalf("Transport error: %v", err)\n\t}', '')

with open("cmd/khepra-mcp/main.go", "w") as f:
    f.write(s)
