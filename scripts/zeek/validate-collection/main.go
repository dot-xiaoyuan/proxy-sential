// Read-only validation using the application's collection configuration loader.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"proxy-sentinel/internal/discovery"
)

func main() {
	if len(os.Args) != 2 || os.Args[1] == "" {
		fmt.Fprintln(os.Stderr, "usage: validate-collection /absolute/path/candidate.json")
		os.Exit(2)
	}
	config, err := discovery.LoadCollectionConfig(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "collection rejected:", err)
		os.Exit(1)
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
		"valid": true, "version": config.Version,
		"protocol_count": len(config.Protocols), "applied": false,
	})
}
