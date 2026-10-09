package controlplane

import (
	"fmt"
	"io"
	"math"
)

// This is the filesystem containing / in the control-plane process namespace.
// It does not claim to measure separately mounted PostgreSQL or Docker volumes.
type rootFilesystemStatus struct {
	Path              string   `json:"path"`
	TotalBytes        uint64   `json:"total_bytes"`
	UsedBytes         uint64   `json:"used_bytes"`
	AvailableBytes    uint64   `json:"available_bytes"`
	UsedPercent       float64  `json:"used_percent"`
	InodesTotal       *uint64  `json:"inodes_total,omitempty"`
	InodesFree        *uint64  `json:"inodes_free,omitempty"`
	InodesUsedPercent *float64 `json:"inodes_used_percent,omitempty"`
}

type rootFilesystemCounters struct {
	blockSize, blocks, freeBlocks, availableBlocks uint64
	files, freeFiles                               uint64
}

func rootFilesystemFromCounters(c rootFilesystemCounters) (*rootFilesystemStatus, error) {
	if c.blockSize == 0 || c.blocks == 0 || c.blocks > math.MaxInt64/c.blockSize || c.freeBlocks > c.blocks || c.availableBlocks > c.freeBlocks {
		return nil, fmt.Errorf("invalid root filesystem capacity counters")
	}
	s := &rootFilesystemStatus{
		Path:           "/",
		TotalBytes:     c.blocks * c.blockSize,
		UsedBytes:      (c.blocks - c.freeBlocks) * c.blockSize,
		AvailableBytes: c.availableBlocks * c.blockSize,
		UsedPercent:    100,
	}
	// Match df's usable-space ratio. Reserved blocks are excluded from its
	// denominator; they must not be presented as available application capacity.
	if denominator := s.UsedBytes + s.AvailableBytes; denominator > 0 {
		s.UsedPercent = float64(s.UsedBytes) / float64(denominator) * 100
	}
	if c.files != 0 && c.files != math.MaxUint64 {
		if c.freeFiles > c.files || c.files > math.MaxInt64 {
			return nil, fmt.Errorf("invalid root filesystem inode counters")
		}
		percent := float64(c.files-c.freeFiles) / float64(c.files) * 100
		s.InodesTotal, s.InodesFree, s.InodesUsedPercent = &c.files, &c.freeFiles, &percent
	}
	return s, nil
}

func writeRootFilesystemMetrics(w io.Writer, status *rootFilesystemStatus, probeError string) {
	if status == nil && probeError == "" {
		return
	}
	fmt.Fprint(w, "# HELP proxy_sentinel_root_filesystem_probe_success Whether the root filesystem capacity probe succeeded.\n# TYPE proxy_sentinel_root_filesystem_probe_success gauge\n")
	if status == nil {
		fmt.Fprint(w, "proxy_sentinel_root_filesystem_probe_success 0\n")
		return
	}
	fmt.Fprint(w, "proxy_sentinel_root_filesystem_probe_success 1\n")
	for _, metric := range []struct {
		name, help string
		value      uint64
	}{
		{"total_bytes", "Root filesystem total size in bytes.", status.TotalBytes},
		{"used_bytes", "Root filesystem allocated size in bytes.", status.UsedBytes},
		{"available_bytes", "Root filesystem bytes available to unprivileged users.", status.AvailableBytes},
	} {
		name := "proxy_sentinel_root_filesystem_" + metric.name
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n%s %d\n", name, metric.help, name, name, metric.value)
	}
	if status.InodesTotal != nil && status.InodesFree != nil {
		fmt.Fprintf(w, "# HELP proxy_sentinel_root_filesystem_inodes_total Root filesystem total inodes.\n# TYPE proxy_sentinel_root_filesystem_inodes_total gauge\nproxy_sentinel_root_filesystem_inodes_total %d\n", *status.InodesTotal)
		fmt.Fprintf(w, "# HELP proxy_sentinel_root_filesystem_inodes_free Root filesystem free inodes.\n# TYPE proxy_sentinel_root_filesystem_inodes_free gauge\nproxy_sentinel_root_filesystem_inodes_free %d\n", *status.InodesFree)
	}
}
