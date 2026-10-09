package controlplane

import (
	"bytes"
	"math"
	"strings"
	"testing"
)

func TestRootFilesystemCapacityAccounting(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		blocks, free, available uint64
		percent                 float64
	}{
		{"reserved blocks are not available", 100, 20, 10, 80.0 / 90 * 100},
		{"empty filesystem", 100, 100, 100, 0},
		{"full filesystem", 100, 0, 0, 100},
		{"all space reserved", 100, 100, 0, 100},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, err := rootFilesystemFromCounters(rootFilesystemCounters{blockSize: 4096, blocks: tc.blocks, freeBlocks: tc.free, availableBlocks: tc.available, files: 1000, freeFiles: 50})
			if err != nil || status.Path != "/" || status.TotalBytes != tc.blocks*4096 || status.UsedBytes != (tc.blocks-tc.free)*4096 || status.AvailableBytes != tc.available*4096 || math.Abs(status.UsedPercent-tc.percent) > 1e-8 {
				t.Fatalf("reserved and usable capacity must remain distinct: %+v %v", status, err)
			}
			if status.InodesTotal == nil || *status.InodesTotal != 1000 || status.InodesFree == nil || *status.InodesFree != 50 || status.InodesUsedPercent == nil || *status.InodesUsedPercent != 95 {
				t.Fatalf("inode pressure must not be confused with byte pressure: %+v", status)
			}
		})
	}
}

func TestRootFilesystemRejectsInvalidCounters(t *testing.T) {
	for _, tc := range []struct {
		name string
		c    rootFilesystemCounters
	}{
		{"zero size", rootFilesystemCounters{blockSize: 4096}},
		{"zero block size", rootFilesystemCounters{blocks: 100}},
		{"free exceeds size", rootFilesystemCounters{blockSize: 4096, blocks: 100, freeBlocks: 101}},
		{"available exceeds free", rootFilesystemCounters{blockSize: 4096, blocks: 100, freeBlocks: 10, availableBlocks: 11}},
		{"byte overflow", rootFilesystemCounters{blockSize: 4096, blocks: math.MaxUint64}},
		{"inode inconsistency", rootFilesystemCounters{blockSize: 4096, blocks: 100, files: 1, freeFiles: 2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if status, err := rootFilesystemFromCounters(tc.c); err == nil || status != nil {
				t.Fatal("invalid capacity must not wrap to a plausible zero/full value", status, err)
			}
		})
	}
}

func TestRootFilesystemOmitsUnsupportedInodeCounters(t *testing.T) {
	for _, count := range []uint64{0, math.MaxUint64} {
		status, err := rootFilesystemFromCounters(rootFilesystemCounters{blockSize: 4096, blocks: 100, freeBlocks: 20, availableBlocks: 10, files: count, freeFiles: count})
		if err != nil || status.InodesTotal != nil || status.InodesFree != nil || status.InodesUsedPercent != nil {
			t.Fatal("unsupported inode counters must stay absent", status, err)
		}
	}
}

func TestRootFilesystemMetricsDoNotPublishFalseZeroOnProbeFailure(t *testing.T) {
	var out bytes.Buffer
	writeRootFilesystemMetrics(&out, nil, "probe failed")
	if !strings.Contains(out.String(), "proxy_sentinel_root_filesystem_probe_success 0") || strings.Contains(out.String(), "proxy_sentinel_root_filesystem_available_bytes") {
		t.Fatal("probe failure must not claim zero available space", out.String())
	}
	out.Reset()
	writeRootFilesystemMetrics(&out, nil, "")
	if out.Len() != 0 {
		t.Fatal("unsupported platform must omit capacity series", out.String())
	}
	out.Reset()
	status, _ := rootFilesystemFromCounters(rootFilesystemCounters{blockSize: 4096, blocks: 100, freeBlocks: 20, availableBlocks: 10})
	writeRootFilesystemMetrics(&out, status, "")
	if !strings.Contains(out.String(), "proxy_sentinel_root_filesystem_available_bytes 40960") || !strings.Contains(out.String(), "proxy_sentinel_root_filesystem_probe_success 1") || strings.Contains(out.String(), "proxy_sentinel_root_filesystem_inodes") {
		t.Fatal("valid capacity and absent inode counters must retain their meanings", out.String())
	}
}
