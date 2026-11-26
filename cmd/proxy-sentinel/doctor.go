package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/cookiejar"
	"os"
	"sort"
	"strings"
	"time"
)

type doctorCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"` // PASS, WARN, FAIL
	Summary string `json:"summary"`
	Detail  string `json:"detail,omitempty"`
}

type doctorLatencyResult struct {
	Name   string  `json:"name"`
	Path   string  `json:"path"`
	Samples int    `json:"samples"`
	Errors int     `json:"errors"`
	P50Ms  float64 `json:"p50_ms"`
	P95Ms  float64 `json:"p95_ms"`
	P99Ms  float64 `json:"p99_ms"`
	MaxMs  float64 `json:"max_ms"`
	Status string  `json:"status"`
}

type doctorReport struct {
	CheckedAt      string                `json:"checked_at"`
	ControlPlane   string                `json:"control_plane"`
	HealthFile     string                `json:"health_file"`
	OverallStatus  string                `json:"overall_status"` // PASS, WARN, FAIL
	Checks         []doctorCheck         `json:"checks"`
	LatencyProbes  []doctorLatencyResult `json:"latency_probes"`
}

type doctorPassiveHealthFile struct {
	SampledAt   string              `json:"sampled_at"`
	Release     string              `json:"release"`
	Alerts      []string            `json:"alerts"`
	Errors      map[string]string   `json:"errors"`
	FailedUnits []string            `json:"failed_units"`
	Timers      []struct {
		Unit   string `json:"unit"`
		Active bool   `json:"active"`
	} `json:"timers"`
	Disk struct {
		Available int64 `json:"available"`
		Total     int64 `json:"total"`
	} `json:"disk"`
	Storage struct {
		PostgresBytes   int64 `json:"postgres_bytes"`
		ClickHouseBytes int64 `json:"clickhouse_bytes"`
		ZeekLogsBytes   int64 `json:"zeek_logs_bytes"`
	} `json:"storage"`
	Watermarks []struct {
		SensorID        string `json:"sensor_id"`
		SourceEventType string `json:"source_event_type"`
		LagSeconds      *int64 `json:"lag_seconds"`
	} `json:"watermarks"`
}

func runDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	addr := fs.String("addr", firstEnv("PROXY_SENTINEL_DOCTOR_ADDR", "http://127.0.0.1:18080"), "control-plane base URL")
	healthFile := fs.String("health-file", firstEnv("PROXY_SENTINEL_PASSIVE_HEALTH_FILE", "/opt/proxy-sentinel/data/passive-health/latest.json"), "passive-health snapshot JSON path")
	samples := fs.Int("samples", 20, "bounded HTTP latency probe sample count per endpoint")
	p95LimitMs := fs.Float64("p95-limit-ms", 500, "P95 latency gate in milliseconds")
	p99LimitMs := fs.Float64("p99-limit-ms", 1000, "P99 latency gate in milliseconds")
	maxDiskUsedPct := fs.Float64("max-disk-used-pct", 80, "disk usage warning/fail threshold percent")
	maxLagSec := fs.Int64("max-lag-seconds", 900, "max discovery source watermark lag threshold in seconds")
	authUser := fs.String("auth-user", os.Getenv("PROXY_SENTINEL_DOCTOR_USER"), "optional control-plane login username for authenticated latency probes")
	authPass := fs.String("auth-pass", os.Getenv("PROXY_SENTINEL_DOCTOR_PASSWORD"), "optional control-plane login password")
	format := fs.String("format", "text", "output format: text or json")
	timeout := fs.Duration("timeout", 10*time.Second, "per-request HTTP timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *samples < 1 || *samples > 200 {
		return fmt.Errorf("--samples must be between 1 and 200")
	}

	report := executeDoctor(doctorOptions{
		Addr:           strings.TrimRight(strings.TrimSpace(*addr), "/"),
		HealthFile:     strings.TrimSpace(*healthFile),
		Samples:        *samples,
		P95LimitMs:     *p95LimitMs,
		P99LimitMs:     *p99LimitMs,
		MaxDiskUsedPct: *maxDiskUsedPct,
		MaxLagSeconds:  *maxLagSec,
		AuthUser:       strings.TrimSpace(*authUser),
		AuthPass:       *authPass,
		Timeout:        *timeout,
	})

	if strings.EqualFold(*format, "json") {
		if err := writeJSON(os.Stdout, report); err != nil {
			return err
		}
	} else {
		printDoctorText(os.Stdout, report)
	}
	if report.OverallStatus == "FAIL" {
		return fmt.Errorf("doctor gate failed")
	}
	return nil
}

type doctorOptions struct {
	Addr           string
	HealthFile     string
	Samples        int
	P95LimitMs     float64
	P99LimitMs     float64
	MaxDiskUsedPct float64
	MaxLagSeconds  int64
	AuthUser       string
	AuthPass       string
	Timeout        time.Duration
}

func executeDoctor(opts doctorOptions) doctorReport {
	now := time.Now().UTC()
	report := doctorReport{
		CheckedAt:     now.Format(time.RFC3339),
		ControlPlane:  opts.Addr,
		HealthFile:    opts.HealthFile,
		OverallStatus: "PASS",
		Checks:        []doctorCheck{},
		LatencyProbes: []doctorLatencyResult{},
	}

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Timeout: opts.Timeout, Jar: jar}

	// 1. /readyz 检查
	readyCheck := checkReadyz(client, opts.Addr+"/readyz")
	report.Checks = append(report.Checks, readyCheck)

	// 2. /metrics 指标检查
	metricsCheck := checkPrometheusMetrics(client, opts.Addr+"/metrics")
	report.Checks = append(report.Checks, metricsCheck)

	// 3. passive-health 快照检查（磁盘、水位、定时器、失败单元与告警）
	report.Checks = append(report.Checks, checkPassiveHealthFile(opts.HealthFile, now, opts.MaxDiskUsedPct, opts.MaxLagSeconds)...)

	// 4. 有界 HTTP 延迟门禁探测
	report.LatencyProbes = append(report.LatencyProbes, probeEndpointLatency(client, "readyz", opts.Addr, "/readyz", opts.Samples, opts.P95LimitMs, opts.P99LimitMs))
	if opts.AuthUser != "" && opts.AuthPass != "" {
		if err := loginControlPlane(client, opts.Addr, opts.AuthUser, opts.AuthPass); err != nil {
			report.Checks = append(report.Checks, doctorCheck{
				Name:    "auth_latency_probe",
				Status:  "FAIL",
				Summary: "登录控制面失败，无法执行认证接口时延验收",
				Detail:  err.Error(),
			})
		} else {
			endpoints := []struct{ name, path string }{
				{"discovery_list_24h", "/api/v1/discovery/devices?limit=50&window=24h"},
				{"discovery_metadata_24h", "/api/v1/discovery/devices/metadata?mode=passive&identity_scope=devices&window=24h"},
				{"discovery_coverage_24h", "/api/v1/discovery/devices/coverage-report?window=24h"},
				{"passive_health_api", "/api/v1/ingest/passive-health"},
			}
			for _, ep := range endpoints {
				res := probeEndpointLatency(client, ep.name, opts.Addr, ep.path, opts.Samples, opts.P95LimitMs, opts.P99LimitMs)
				report.LatencyProbes = append(report.LatencyProbes, res)
				report.Checks = append(report.Checks, doctorCheck{
					Name:    "latency_" + ep.name,
					Status:  res.Status,
					Summary: fmt.Sprintf("P50=%.1fms P95=%.1fms P99=%.1fms (samples=%d errors=%d)", res.P50Ms, res.P95Ms, res.P99Ms, res.Samples, res.Errors),
				})
			}
		}
	} else {
		report.Checks = append(report.Checks, doctorCheck{
			Name:    "auth_latency_probe",
			Status:  "WARN",
			Summary: "未提供 --auth-user/--auth-pass，已跳过认证查询接口 P95/P99 采样（已完成 /readyz 探测）",
		})
	}

	// 汇总总体状态
	for _, c := range report.Checks {
		if c.Status == "FAIL" {
			report.OverallStatus = "FAIL"
			break
		}
		if c.Status == "WARN" && report.OverallStatus == "PASS" {
			report.OverallStatus = "WARN"
		}
	}
	return report
}

func checkReadyz(client *http.Client, url string) doctorCheck {
	ctx, cancel := context.WithTimeout(context.Background(), client.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return doctorCheck{Name: "control_plane_readyz", Status: "FAIL", Summary: "构造 readyz 请求失败", Detail: err.Error()}
	}
	resp, err := client.Do(req)
	if err != nil {
		return doctorCheck{Name: "control_plane_readyz", Status: "FAIL", Summary: "控制面 /readyz 不可达", Detail: err.Error()}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if resp.StatusCode != http.StatusOK {
		return doctorCheck{
			Name:    "control_plane_readyz",
			Status:  "FAIL",
			Summary: fmt.Sprintf("/readyz 返回 HTTP %d", resp.StatusCode),
			Detail:  strings.TrimSpace(string(body)),
		}
	}
	return doctorCheck{Name: "control_plane_readyz", Status: "PASS", Summary: "/readyz HTTP 200 正常"}
}

func checkPrometheusMetrics(client *http.Client, url string) doctorCheck {
	resp, err := client.Get(url)
	if err != nil {
		return doctorCheck{Name: "prometheus_metrics", Status: "WARN", Summary: "/metrics 不可达", Detail: err.Error()}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if resp.StatusCode != http.StatusOK {
		return doctorCheck{Name: "prometheus_metrics", Status: "WARN", Summary: fmt.Sprintf("/metrics 返回 HTTP %d", resp.StatusCode)}
	}
	text := string(body)
	if !strings.Contains(text, "proxy_sentinel_passive_health_available") {
		return doctorCheck{Name: "prometheus_metrics", Status: "WARN", Summary: "/metrics 可访问但缺少 proxy_sentinel_passive_health_* 指标"}
	}
	return doctorCheck{Name: "prometheus_metrics", Status: "PASS", Summary: "/metrics 正常输出被动健康与存储容量指标"}
}

func checkPassiveHealthFile(path string, now time.Time, maxDiskUsedPct float64, maxLagSec int64) []doctorCheck {
	raw, err := os.ReadFile(path)
	if err != nil {
		return []doctorCheck{{
			Name:    "passive_health_snapshot",
			Status:  "FAIL",
			Summary: "无法读取被动健康巡检快照",
			Detail:  err.Error(),
		}}
	}
	var snap doctorPassiveHealthFile
	if err := json.Unmarshal(raw, &snap); err != nil {
		return []doctorCheck{{
			Name:    "passive_health_snapshot",
			Status:  "FAIL",
			Summary: "被动健康巡检快照 JSON 解析失败",
			Detail:  err.Error(),
		}}
	}
	checks := []doctorCheck{}

	// 快照新鲜度
	if sampledAt, err := time.Parse(time.RFC3339, snap.SampledAt); err == nil {
		age := int64(now.Sub(sampledAt).Seconds())
		if age < 0 {
			age = 0
		}
		if age > 1500 {
			checks = append(checks, doctorCheck{
				Name:    "passive_health_freshness",
				Status:  "FAIL",
				Summary: fmt.Sprintf("巡检快照已过期 %d 秒（> 1500s）", age),
				Detail:  "sampled_at=" + snap.SampledAt,
			})
		} else {
			checks = append(checks, doctorCheck{
				Name:    "passive_health_freshness",
				Status:  "PASS",
				Summary: fmt.Sprintf("巡检快照新鲜（距今 %d 秒，release=%s）", age, snap.Release),
			})
		}
	} else {
		checks = append(checks, doctorCheck{Name: "passive_health_freshness", Status: "WARN", Summary: "快照缺少有效 sampled_at 时间戳"})
	}

	// 失败 systemd 单元
	if len(snap.FailedUnits) > 0 {
		checks = append(checks, doctorCheck{
			Name:    "systemd_failed_units",
			Status:  "FAIL",
			Summary: fmt.Sprintf("存在 %d 个失败的 systemd 单元", len(snap.FailedUnits)),
			Detail:  strings.Join(snap.FailedUnits, ", "),
		})
	} else {
		checks = append(checks, doctorCheck{Name: "systemd_failed_units", Status: "PASS", Summary: "失败 systemd 单元为 0"})
	}

	// 定时器激活检查
	activeTimers := 0
	inactiveNames := []string{}
	for _, t := range snap.Timers {
		if t.Active {
			activeTimers++
		} else {
			inactiveNames = append(inactiveNames, t.Unit)
		}
	}
	if len(inactiveNames) > 0 {
		checks = append(checks, doctorCheck{
			Name:    "systemd_timers",
			Status:  "FAIL",
			Summary: fmt.Sprintf("存在未激活的运维定时器：%s", strings.Join(inactiveNames, ", ")),
		})
	} else if activeTimers == 0 {
		checks = append(checks, doctorCheck{Name: "systemd_timers", Status: "WARN", Summary: "快照未上报任何定时器状态"})
	} else {
		checks = append(checks, doctorCheck{Name: "systemd_timers", Status: "PASS", Summary: fmt.Sprintf("%d 个运维定时器全部处于 active 状态", activeTimers)})
	}

	// 磁盘容量使用率
	if snap.Disk.Total > 0 {
		usedPct := (1.0 - float64(snap.Disk.Available)/float64(snap.Disk.Total)) * 100.0
		availGiB := float64(snap.Disk.Available) / (1024 * 1024 * 1024)
		status := "PASS"
		if usedPct >= 90 {
			status = "FAIL"
		} else if usedPct >= maxDiskUsedPct {
			status = "WARN"
		}
		checks = append(checks, doctorCheck{
			Name:    "disk_capacity",
			Status:  status,
			Summary: fmt.Sprintf("数据盘使用率 %.1f%%，可用 %.1f GiB（阈值 %.0f%%）", usedPct, availGiB, maxDiskUsedPct),
		})
	} else {
		checks = append(checks, doctorCheck{Name: "disk_capacity", Status: "WARN", Summary: "快照未包含磁盘容量统计"})
	}

	// 发现源水位滞后
	var maxLag int64
	slowestSource := ""
	for _, wm := range snap.Watermarks {
		if wm.LagSeconds != nil && *wm.LagSeconds > maxLag {
			maxLag = *wm.LagSeconds
			slowestSource = wm.SourceEventType
		}
	}
	if maxLag > maxLagSec {
		checks = append(checks, doctorCheck{
			Name:    "discovery_watermark_lag",
			Status:  "FAIL",
			Summary: fmt.Sprintf("发现源最大滞后 %d 秒（%s），超过阈值 %d 秒", maxLag, slowestSource, maxLagSec),
		})
	} else {
		checks = append(checks, doctorCheck{
			Name:    "discovery_watermark_lag",
			Status:  "PASS",
			Summary: fmt.Sprintf("全部 %d 个发现源水位正常，最大滞后 %d 秒（阈值 %d 秒）", len(snap.Watermarks), maxLag, maxLagSec),
		})
	}

	// 巡检告警与探针错误
	if len(snap.Errors) > 0 {
		keys := make([]string, 0, len(snap.Errors))
		for k := range snap.Errors {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		checks = append(checks, doctorCheck{
			Name:    "passive_health_errors",
			Status:  "WARN",
			Summary: fmt.Sprintf("巡检存在 %d 项子探针异常：%s", len(keys), strings.Join(keys, ", ")),
		})
	}
	if len(snap.Alerts) > 0 {
		checks = append(checks, doctorCheck{
			Name:    "passive_health_alerts",
			Status:  "WARN",
			Summary: fmt.Sprintf("巡检存在 %d 项提醒：%s", len(snap.Alerts), strings.Join(snap.Alerts, ", ")),
		})
	}
	return checks
}

func loginControlPlane(client *http.Client, baseURL, username, password string) error {
	payload, _ := json.Marshal(map[string]string{
		"username": username,
		"password": password,
	})
	resp, err := client.Post(baseURL+"/api/v1/auth/login", "application/json", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func probeEndpointLatency(client *http.Client, name, baseURL, path string, samples int, p95LimitMs, p99LimitMs float64) doctorLatencyResult {
	durations := make([]float64, 0, samples)
	errs := 0
	for i := 0; i < samples; i++ {
		started := time.Now()
		resp, err := client.Get(baseURL + path)
		elapsed := float64(time.Since(started).Microseconds()) / 1000.0
		if err != nil {
			errs++
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 2<<20))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			errs++
			continue
		}
		durations = append(durations, elapsed)
	}
	sort.Float64s(durations)
	res := doctorLatencyResult{
		Name:    name,
		Path:    path,
		Samples: len(durations),
		Errors:  errs,
		P50Ms:   percentileMs(durations, 50),
		P95Ms:   percentileMs(durations, 95),
		P99Ms:   percentileMs(durations, 99),
		Status:  "PASS",
	}
	if len(durations) > 0 {
		res.MaxMs = round1(durations[len(durations)-1])
	}
	if errs > 0 || len(durations) == 0 || res.P95Ms > p95LimitMs || res.P99Ms > p99LimitMs {
		res.Status = "FAIL"
	}
	return res
}

func percentileMs(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(math.Ceil((p/100.0)*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return round1(sorted[idx])
}

func round1(v float64) float64 {
	return math.Round(v*10) / 10
}

func printDoctorText(w io.Writer, r doctorReport) {
	fmt.Fprintf(w, "Proxy Sentinel 生产健康与验收门禁 [%s] (%s)\n", r.OverallStatus, r.CheckedAt)
	fmt.Fprintf(w, "控制面: %s | 巡检快照: %s\n\n", r.ControlPlane, r.HealthFile)
	for _, c := range r.Checks {
		fmt.Fprintf(w, "[%-4s] %-26s %s\n", c.Status, c.Name, c.Summary)
		if c.Detail != "" {
			fmt.Fprintf(w, "       %s\n", c.Detail)
		}
	}
	if len(r.LatencyProbes) > 0 {
		fmt.Fprintln(w, "\n有界接口时延采样:")
		for _, p := range r.LatencyProbes {
			fmt.Fprintf(w, "[%-4s] %-24s P50=%5.1fms  P95=%5.1fms  P99=%5.1fms  Max=%5.1fms  (n=%d err=%d)\n",
				p.Status, p.Name, p.P50Ms, p.P95Ms, p.P99Ms, p.MaxMs, p.Samples, p.Errors)
		}
	}
}
