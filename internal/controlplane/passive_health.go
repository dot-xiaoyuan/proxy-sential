package controlplane

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultPassiveHealthSnapshotPath = "/opt/proxy-sentinel/data/passive-health/latest.json"
	maxPassiveHealthSnapshotBytes    = 2 << 20
	passiveHealthStaleAfterSeconds   = 25 * 60
)

// PassiveHealthDisk 表示磁盘总量与可用字节。
type PassiveHealthDisk struct {
	Available int64 `json:"available"`
	Total     int64 `json:"total"`
}

// PassiveHealthStorage 表示核心数据目录/库占用字节数。
type PassiveHealthStorage struct {
	PostgresBytes   int64 `json:"postgres_bytes"`
	ClickHouseBytes int64 `json:"clickhouse_bytes"`
	ZeekLogsBytes   int64 `json:"zeek_logs_bytes"`
}

// PassiveHealthArchiveQueue 表示归档与硬件投影队列状态。
type PassiveHealthArchiveQueue struct {
	HardwareWaiting int64 `json:"hardware_waiting"`
	HardwareErrors  int64 `json:"hardware_errors"`
	Waiting         int64 `json:"waiting"`
	Retrying        int64 `json:"retrying"`
	Failed          int64 `json:"failed"`
}

// PassiveHealthWatermark 表示单采集源消费水位。
type PassiveHealthWatermark struct {
	SensorID        string `json:"sensor_id"`
	SourceEventType string `json:"source_event_type"`
	CursorTimestamp string `json:"cursor_timestamp"`
	UpdatedAt       string `json:"updated_at"`
	LagSeconds      int64  `json:"lag_seconds,omitempty"`
}

// PassiveHealthTimer 表示已启用的维护定时器状态。
type PassiveHealthTimer struct {
	Unit   string `json:"unit"`
	Active bool   `json:"active"`
}

// PassiveHealthReadyz 表示巡检采样的就绪接口摘要。
type PassiveHealthReadyz struct {
	HTTP       int               `json:"http"`
	Status     string            `json:"status"`
	Components map[string]string `json:"components,omitempty"`
}

// PassiveHealthSnapshot 是 passive_health.py 落盘的最新只读巡检快照。
type PassiveHealthSnapshot struct {
	Available              bool                       `json:"available"`
	Stale                  bool                       `json:"stale"`
	AgeSeconds             int64                      `json:"age_seconds"`
	SampledAt              string                     `json:"sampled_at,omitempty"`
	Release                string                     `json:"release,omitempty"`
	Alerts                 []string                   `json:"alerts"`
	Errors                 map[string]string          `json:"errors,omitempty"`
	FailedUnits            []string                   `json:"failed_units"`
	Timers                 []PassiveHealthTimer       `json:"timers,omitempty"`
	Disk                   *PassiveHealthDisk         `json:"disk,omitempty"`
	Storage                *PassiveHealthStorage      `json:"storage,omitempty"`
	ArchiveHardware        *PassiveHealthArchiveQueue `json:"archive_hardware,omitempty"`
	Readyz                 *PassiveHealthReadyz       `json:"readyz,omitempty"`
	Watermarks             []PassiveHealthWatermark   `json:"watermarks,omitempty"`
	MaxWatermarkLagSeconds int64                      `json:"max_watermark_lag_seconds"`
}

func passiveHealthSnapshotPath() string {
	if custom := strings.TrimSpace(os.Getenv("PROXY_SENTINEL_PASSIVE_HEALTH_FILE")); custom != "" {
		return custom
	}
	return defaultPassiveHealthSnapshotPath
}

func loadPassiveHealthSnapshot(path string, now time.Time) PassiveHealthSnapshot {
	out := PassiveHealthSnapshot{
		Available:   false,
		Alerts:      []string{},
		FailedUnits: []string{},
		Timers:      []PassiveHealthTimer{},
		Watermarks:  []PassiveHealthWatermark{},
	}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxPassiveHealthSnapshotBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxPassiveHealthSnapshotBytes {
		return out
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return PassiveHealthSnapshot{
			Available:   false,
			Alerts:      []string{},
			FailedUnits: []string{},
		}
	}
	out.Available = true
	if out.Alerts == nil {
		out.Alerts = []string{}
	}
	if out.FailedUnits == nil {
		out.FailedUnits = []string{}
	}
	if out.Timers == nil {
		out.Timers = []PassiveHealthTimer{}
	}
	if out.Watermarks == nil {
		out.Watermarks = []PassiveHealthWatermark{}
	}
	if sampled, parseErr := time.Parse(time.RFC3339Nano, out.SampledAt); parseErr == nil {
		age := int64(now.Sub(sampled).Seconds())
		if age < 0 {
			age = 0
		}
		out.AgeSeconds = age
		out.Stale = age > passiveHealthStaleAfterSeconds
		// 若旧快照未内嵌单源滞后，按采样时间补算
		var maxLag int64
		for i := range out.Watermarks {
			if out.Watermarks[i].LagSeconds == 0 {
				if cur, curErr := time.Parse(time.RFC3339Nano, out.Watermarks[i].CursorTimestamp); curErr == nil {
					lag := int64(sampled.Sub(cur).Seconds())
					if lag < 0 {
						lag = 0
					}
					out.Watermarks[i].LagSeconds = lag
				}
			}
			if out.Watermarks[i].LagSeconds > maxLag {
				maxLag = out.Watermarks[i].LagSeconds
			}
		}
		if out.MaxWatermarkLagSeconds == 0 {
			out.MaxWatermarkLagSeconds = maxLag
		}
	}
	return out
}

func (s *Server) handlePassiveHealth(w http.ResponseWriter, _ *http.Request) {
	snap := loadPassiveHealthSnapshot(passiveHealthSnapshotPath(), time.Now().UTC())
	writeJSON(w, http.StatusOK, snap)
}

// passiveHealthMetrics 在标准 Prometheus /metrics 出口追加被动发现站点的容量、水位与告警指标。
func (s *Server) passiveHealthMetrics(w http.ResponseWriter) {
	snap := loadPassiveHealthSnapshot(passiveHealthSnapshotPath(), time.Now().UTC())
	avail := 0
	if snap.Available {
		avail = 1
	}
	fmt.Fprintf(w, "# HELP proxy_sentinel_passive_health_available Whether the passive health snapshot file is readable.\n# TYPE proxy_sentinel_passive_health_available gauge\nproxy_sentinel_passive_health_available %d\n", avail)
	if !snap.Available {
		return
	}
	fmt.Fprintf(w, "# HELP proxy_sentinel_passive_health_snapshot_age_seconds Age in seconds of the latest passive health snapshot.\n# TYPE proxy_sentinel_passive_health_snapshot_age_seconds gauge\nproxy_sentinel_passive_health_snapshot_age_seconds %d\n", snap.AgeSeconds)
	fmt.Fprintf(w, "# HELP proxy_sentinel_passive_health_alerts_total Number of active alerts in the latest passive health snapshot.\n# TYPE proxy_sentinel_passive_health_alerts_total gauge\nproxy_sentinel_passive_health_alerts_total %d\n", len(snap.Alerts))
	fmt.Fprintf(w, "# HELP proxy_sentinel_passive_health_max_watermark_lag_seconds Maximum passive discovery source lag in seconds.\n# TYPE proxy_sentinel_passive_health_max_watermark_lag_seconds gauge\nproxy_sentinel_passive_health_max_watermark_lag_seconds %d\n", snap.MaxWatermarkLagSeconds)
	if snap.Disk != nil && snap.Disk.Total > 0 {
		usedRatio := float64(snap.Disk.Total-snap.Disk.Available) / float64(snap.Disk.Total)
		fmt.Fprintf(w, "# HELP proxy_sentinel_passive_health_disk_used_ratio Used ratio of the data filesystem.\n# TYPE proxy_sentinel_passive_health_disk_used_ratio gauge\nproxy_sentinel_passive_health_disk_used_ratio %.4f\n", usedRatio)
		fmt.Fprintf(w, "proxy_sentinel_passive_health_disk_available_bytes %d\n", snap.Disk.Available)
	}
	if snap.Storage != nil {
		fmt.Fprint(w, "# HELP proxy_sentinel_passive_health_storage_bytes Bytes used by core storage components.\n# TYPE proxy_sentinel_passive_health_storage_bytes gauge\n")
		if snap.Storage.PostgresBytes >= 0 {
			fmt.Fprintf(w, "proxy_sentinel_passive_health_storage_bytes{component=\"postgres\"} %d\n", snap.Storage.PostgresBytes)
		}
		if snap.Storage.ClickHouseBytes >= 0 {
			fmt.Fprintf(w, "proxy_sentinel_passive_health_storage_bytes{component=\"clickhouse\"} %d\n", snap.Storage.ClickHouseBytes)
		}
		if snap.Storage.ZeekLogsBytes >= 0 {
			fmt.Fprintf(w, "proxy_sentinel_passive_health_storage_bytes{component=\"zeek\"} %d\n", snap.Storage.ZeekLogsBytes)
		}
	}
	if snap.ArchiveHardware != nil {
		fmt.Fprintf(w, "proxy_sentinel_passive_health_archive_failed_rows %d\n", snap.ArchiveHardware.Failed)
		fmt.Fprintf(w, "proxy_sentinel_passive_health_hardware_waiting_rows %d\n", snap.ArchiveHardware.HardwareWaiting)
	}
	if len(snap.Watermarks) > 0 {
		fmt.Fprint(w, "# HELP proxy_sentinel_passive_health_source_lag_seconds Per-source passive discovery watermark lag in seconds.\n# TYPE proxy_sentinel_passive_health_source_lag_seconds gauge\n")
		for _, wm := range snap.Watermarks {
			fmt.Fprintf(w, "proxy_sentinel_passive_health_source_lag_seconds{sensor_id=%s,source=%s} %d\n",
				strconv.Quote(wm.SensorID), strconv.Quote(wm.SourceEventType), wm.LagSeconds)
		}
	}
}
