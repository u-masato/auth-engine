package resource_test

import (
	"fmt"

	"github.com/muno/auth-engine/resource"
)

// ExampleNormalize は resource indicator（RFC 8707 §2）の正規形を示す。
// scheme と host だけを小文字にし、path と末尾スラッシュはそのまま区別する。
// fragment を含むものは拒否する。
func ExampleNormalize() {
	for _, raw := range []string{
		"HTTPS://MCP.Example.com/Tools",
		"https://mcp.example.com/",
		"https://mcp.example.com#frag",
	} {
		uri, err := resource.Normalize(raw)
		if err != nil {
			fmt.Println("error:", err)
			continue
		}
		fmt.Println(uri)
	}

	// Output:
	// https://mcp.example.com/Tools
	// https://mcp.example.com/
	// error: resource: invalid resource indicator: "https://mcp.example.com#frag" must not contain a fragment
}
