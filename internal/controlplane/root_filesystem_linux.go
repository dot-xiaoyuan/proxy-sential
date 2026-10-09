//go:build linux

package controlplane

import (
	"fmt"
	"syscall"
)

func readRootFilesystemStatus() (*rootFilesystemStatus, error) {
	var counters syscall.Statfs_t
	if err := syscall.Statfs("/", &counters); err != nil {
		return nil, fmt.Errorf("read root filesystem capacity: %w", err)
	}
	blockSize := counters.Frsize
	if blockSize <= 0 {
		blockSize = counters.Bsize
	}
	if blockSize <= 0 {
		return nil, fmt.Errorf("invalid root filesystem block size")
	}
	return rootFilesystemFromCounters(rootFilesystemCounters{
		blockSize: uint64(blockSize), blocks: counters.Blocks, freeBlocks: counters.Bfree,
		availableBlocks: counters.Bavail, files: counters.Files, freeFiles: counters.Ffree,
	})
}
