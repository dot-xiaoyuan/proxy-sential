package main

import (
	"errors"
	"fmt"

	"proxy-sentinel/internal/realtime"
)

func filterLegacyStreamOwnedSources(sensor string, sources []realtime.Source, owners map[string]string) ([]realtime.Source, []realtime.Source, error) {
	if sensor == "" {
		return nil, nil, errors.New("legacy source guard needs a sensor")
	}
	legacy := make([]realtime.Source, 0, len(sources))
	transferred := make([]realtime.Source, 0)
	for _, source := range sources {
		owner := owners[source.Kind+"\x00"+source.Path]
		if owner == "" {
			legacy = append(legacy, source)
			continue
		}
		if owner != sensor {
			return nil, nil, fmt.Errorf("active stream source %s at %s belongs to another sensor", source.Kind, source.Path)
		}
		transferred = append(transferred, source)
	}
	return legacy, transferred, nil
}
