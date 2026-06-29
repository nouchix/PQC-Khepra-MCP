package main

import (
	"fmt"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/mcp"
)

func main() {
	v := mcp.NewLiveViewer()
	fmt.Println("starting listen on 127.0.0.1:8773")
	err := v.ListenAndServe("127.0.0.1:8773")
	fmt.Println("ListenAndServe returned:", err)
}
