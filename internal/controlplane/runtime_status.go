package controlplane

import (
	"bufio"
	"os"
	"runtime"
	runtimemetrics "runtime/metrics"
	"strconv"
	"strings"
	"sync"
	"time"
)

type runtimeSampler struct {
	mu                 sync.Mutex
	lastSampledAt      time.Time
	lastCPUTimeSeconds float64
}

type hostRuntimeStatus struct {
	LogicalCPUs         int                   `json:"logical_cpus"`
	Load1               *float64              `json:"load_1,omitempty"`
	Load5               *float64              `json:"load_5,omitempty"`
	Load15              *float64              `json:"load_15,omitempty"`
	MemoryTotalBytes    *uint64               `json:"memory_total_bytes,omitempty"`
	MemoryUsedBytes     *uint64               `json:"memory_used_bytes,omitempty"`
	MemoryUsedPercent   *float64              `json:"memory_used_percent,omitempty"`
	RootFilesystem      *rootFilesystemStatus `json:"root_filesystem,omitempty"`
	RootFilesystemError string                `json:"root_filesystem_error,omitempty"`
}

type processRuntimeStatus struct {
	CPUPercent          float64 `json:"cpu_percent"`
	ResidentMemoryBytes *uint64 `json:"resident_memory_bytes,omitempty"`
	HeapAllocBytes      uint64  `json:"heap_alloc_bytes"`
	HeapInUseBytes      uint64  `json:"heap_in_use_bytes"`
	Goroutines          int     `json:"goroutines"`
	GOMAXPROCS          int     `json:"gomaxprocs"`
	GCCycles            uint32  `json:"gc_cycles"`
	UptimeSeconds       int64   `json:"uptime_seconds"`
}

type runtimeStatus struct {
	Host      hostRuntimeStatus    `json:"host"`
	Process   processRuntimeStatus `json:"process"`
	SampledAt string               `json:"sampled_at"`
}

func captureRuntimeStatus(sampler *runtimeSampler, startedAt time.Time) runtimeStatus {
	now := time.Now()
	if sampler == nil {
		sampler = &runtimeSampler{}
	}
	if startedAt.IsZero() {
		startedAt = now
	}
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)

	status := runtimeStatus{
		Host: hostRuntimeStatus{LogicalCPUs: runtime.NumCPU()},
		Process: processRuntimeStatus{
			HeapAllocBytes: memory.HeapAlloc,
			HeapInUseBytes: memory.HeapInuse,
			Goroutines:     runtime.NumGoroutine(),
			GOMAXPROCS:     runtime.GOMAXPROCS(0),
			GCCycles:       memory.NumGC,
			UptimeSeconds:  max(0, int64(now.Sub(startedAt).Seconds())),
		},
		SampledAt: now.UTC().Format(time.RFC3339Nano),
	}
	readLinuxHostRuntime(&status.Host)
	rootFilesystem, rootErr := readRootFilesystemStatus()
	status.Host.RootFilesystem = rootFilesystem
	status.Host.RootFilesystemError = errorString(rootErr)
	status.Process.ResidentMemoryBytes = readLinuxResidentMemory()
	status.Process.CPUPercent = sampler.sampleCPUPercent(now, readRuntimeCPUSeconds(), status.Process.GOMAXPROCS)
	return status
}

func (s *runtimeSampler) sampleCPUPercent(now time.Time, cpuTimeSeconds float64, logicalCPUs int) float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	percent := 0.0
	if !s.lastSampledAt.IsZero() && cpuTimeSeconds >= s.lastCPUTimeSeconds {
		elapsed := now.Sub(s.lastSampledAt).Seconds()
		if elapsed > 0 && logicalCPUs > 0 {
			percent = (cpuTimeSeconds - s.lastCPUTimeSeconds) / elapsed / float64(logicalCPUs) * 100
			if percent > 100 {
				percent = 100
			}
		}
	}
	s.lastSampledAt = now
	s.lastCPUTimeSeconds = cpuTimeSeconds
	return percent
}

func readRuntimeCPUSeconds() float64 {
	samples := []runtimemetrics.Sample{
		{Name: "/cpu/classes/total:cpu-seconds"},
		{Name: "/cpu/classes/idle:cpu-seconds"},
	}
	runtimemetrics.Read(samples)
	if samples[0].Value.Kind() != runtimemetrics.KindFloat64 || samples[1].Value.Kind() != runtimemetrics.KindFloat64 {
		return 0
	}
	used := samples[0].Value.Float64() - samples[1].Value.Float64()
	return max(0, used)
}

func readLinuxHostRuntime(status *hostRuntimeStatus) {
	if raw, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(raw))
		if len(fields) >= 3 {
			status.Load1 = parseFloatPointer(fields[0])
			status.Load5 = parseFloatPointer(fields[1])
			status.Load15 = parseFloatPointer(fields[2])
		}
	}
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return
	}
	defer file.Close()
	values := map[string]uint64{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		value, parseErr := strconv.ParseUint(fields[1], 10, 64)
		if parseErr == nil {
			values[strings.TrimSuffix(fields[0], ":")] = value * 1024
		}
	}
	total, available := values["MemTotal"], values["MemAvailable"]
	if available == 0 {
		available = values["MemFree"] + values["Buffers"] + values["Cached"] + values["SReclaimable"]
		if values["Shmem"] < available {
			available -= values["Shmem"]
		}
	}
	if total == 0 {
		return
	}
	used := total
	if available < total {
		used -= available
	}
	percent := float64(used) / float64(total) * 100
	status.MemoryTotalBytes = &total
	status.MemoryUsedBytes = &used
	status.MemoryUsedPercent = &percent
}

func readLinuxResidentMemory() *uint64 {
	file, err := os.Open("/proc/self/status")
	if err != nil {
		return nil
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[0] == "VmRSS:" {
			value, parseErr := strconv.ParseUint(fields[1], 10, 64)
			if parseErr == nil {
				value *= 1024
				return &value
			}
		}
	}
	return nil
}

func parseFloatPointer(value string) *float64 {
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return nil
	}
	return &parsed
}
