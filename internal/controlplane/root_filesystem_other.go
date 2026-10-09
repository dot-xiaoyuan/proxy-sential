//go:build !linux

package controlplane

func readRootFilesystemStatus() (*rootFilesystemStatus, error) { return nil, nil }
