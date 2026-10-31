package controlplane

import (
	"errors"
	"io"
	"os"
	"strings"
)

type discoveryQuarantineState struct {
	Status       string `json:"status"`
	CountAtLeast int    `json:"count_at_least"`
	Truncated    bool   `json:"truncated,omitempty"`
}

func discoveryQuarantinePath() string {
	if path := strings.TrimSpace(os.Getenv("PROXY_SENTINEL_DISCOVERY_QUARANTINE_DIR")); path != "" {
		return path
	}
	return "/var/lib/proxy-sentinel/discovery-spool/discovery-quarantine"
}

func discoveryQuarantineStatus(path string) discoveryQuarantineState {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return discoveryQuarantineState{Status: "clear"}
	}
	if err != nil {
		return discoveryQuarantineState{Status: "unavailable"}
	}
	defer f.Close()
	names, err := f.Readdirnames(201)
	if err != nil && !errors.Is(err, io.EOF) {
		return discoveryQuarantineState{Status: "unavailable"}
	}
	state := discoveryQuarantineState{Status: "clear", Truncated: len(names) >= 201}
	for _, name := range names {
		if strings.HasSuffix(name, ".json") {
			state.CountAtLeast++
		}
	}
	if state.CountAtLeast > 0 {
		state.Status = "blocked"
	} else if state.Truncated {
		state.Status = "unavailable"
	}
	return state
}
