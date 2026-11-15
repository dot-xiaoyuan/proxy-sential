package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"proxy-sentinel/internal/adapter/zeek"
	"proxy-sentinel/internal/discovery"
	"proxy-sentinel/internal/normalized"
	"proxy-sentinel/internal/realtime"
	"proxy-sentinel/internal/store"
	"strings"
	"time"
)

const dhcpMessageReplaySchema = "dhcp-original-file-replay/v1"
const protocolReplaySchema = "protocol-original-file-replay/v1"

type dhcpMessageRecord struct {
	Offset int64  `json:"offset"`
	Length int    `json:"length"`
	SHA256 string `json:"sha256"`
}
type dhcpMessageManifest struct {
	LogKind      string                   `json:"log_kind,omitempty"`
	CaptureScope *normalized.CaptureScope `json:"capture_scope"`
	Schema       string                   `json:"schema"`
	Path         string                   `json:"path"`
	FileID       string                   `json:"file_id"`
	Sensor       string                   `json:"sensor"`
	Interface    string                   `json:"interface"`
	CIDRs        string                   `json:"cidrs"`
	Header       string                   `json:"header"`
	HeaderSHA256 string                   `json:"header_sha256"`
	SnapshotAt   time.Time                `json:"snapshot_at"`
	SnapshotSize int64                    `json:"snapshot_size"`
	FromOffset   int64                    `json:"from_offset"`
	NextOffset   int64                    `json:"next_offset"`
	Records      []dhcpMessageRecord      `json:"records"`
}

func messageDigest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func messageManifestHash(m dhcpMessageManifest) string {
	b, _ := json.Marshal(m)
	return messageDigest(b)
}

// Snapshot pages are bounded by both source bytes and records. The next offset
// includes only complete lines; neither a partial tail nor another page is
// claimed as processed. Only offsets/hashes are stored, never a raw duplicate.
func snapshotDHCPMessages(path, sensor, iface, cidrs string, offset int64, scope *normalized.CaptureScope) (dhcpMessageManifest, error) {
	m := dhcpMessageManifest{CaptureScope: scope, Schema: dhcpMessageReplaySchema, Path: path, Sensor: sensor, Interface: iface, CIDRs: cidrs, FromOffset: offset, SnapshotAt: time.Now().UTC(), Records: []dhcpMessageRecord{}}
	if path == "" || sensor == "" || iface == "" || cidrs == "" || offset < 0 || scope == nil || scope.SensorID != sensor {
		return m, fmt.Errorf("original file, sensor, interface, CIDRs and nonnegative offset required")
	}
	f, err := os.Open(path)
	if err != nil {
		return m, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return m, err
	}
	if !st.Mode().IsRegular() || offset > st.Size() {
		return m, fmt.Errorf("invalid original file or offset")
	}
	m.FileID = realtime.FileIdentity(path, st)
	m.SnapshotSize = st.Size()
	reader := bufio.NewReaderSize(io.NewSectionReader(f, 0, min(st.Size(), 8192)), 8192)
	for {
		line, e := reader.ReadString('\n')
		if e != nil || !strings.HasPrefix(line, "#") {
			break
		}
		m.Header += line
	}
	m.HeaderSHA256 = messageDigest([]byte(m.Header))
	if offset > 0 {
		var prior [1]byte
		if _, err = f.ReadAt(prior[:], offset-1); err != nil || prior[0] != '\n' {
			return m, fmt.Errorf("page offset is not a record boundary")
		}
	}
	reader = bufio.NewReaderSize(io.NewSectionReader(f, offset, min(st.Size()-offset, 2<<20)), 64<<10)
	position := offset
	for len(m.Records) < 5000 {
		line, e := reader.ReadBytes('\n')
		if e == io.EOF {
			break
		}
		if e != nil {
			return m, e
		}
		if len(line) > store.HardwareRepairMaxRowBytes {
			return m, fmt.Errorf("original line exceeds repair bound")
		}
		if position >= int64(len(m.Header)) && line[0] == '#' && !bytes.HasPrefix(line, []byte("#close\t")) {
			return m, fmt.Errorf("original log contains a mid-file header; split at the schema boundary before replay")
		}
		if len(bytes.TrimSpace(line)) > 0 && line[0] != '#' {
			m.Records = append(m.Records, dhcpMessageRecord{position, len(line), messageDigest(line)})
		}
		position += int64(len(line))
	}
	m.NextOffset = position
	return m, nil
}

func snapshotOriginalProtocol(path, sensor, iface, cidrs string, offset int64, scope *normalized.CaptureScope, kind string) (dhcpMessageManifest, error) {
	if kind != "rtsp-device" {
		return dhcpMessageManifest{}, fmt.Errorf("original protocol replay only supports rtsp-device")
	}
	m, err := snapshotDHCPMessages(path, sensor, iface, cidrs, offset, scope)
	if err != nil {
		return m, err
	}
	m.Schema, m.LogKind = protocolReplaySchema, kind
	return m, nil
}

func originalReplayKind(m dhcpMessageManifest) (string, error) {
	if m.Schema == dhcpMessageReplaySchema && m.LogKind == "" {
		return "dhcp-message", nil
	}
	if m.Schema == protocolReplaySchema && m.LogKind == "rtsp-device" {
		return m.LogKind, nil
	}
	return "", fmt.Errorf("unsupported original replay schema or protocol")
}

func readDHCPMessage(m dhcpMessageManifest, r dhcpMessageRecord) (normalized.Event, string, error) {
	var empty normalized.Event
	kind, kindErr := originalReplayKind(m)
	if kindErr != nil {
		return empty, "", kindErr
	}
	if m.CaptureScope == nil || m.CaptureScope.SensorID != m.Sensor || m.Sensor == "" || m.Interface == "" || m.CIDRs == "" || m.SnapshotAt.IsZero() || len(m.Header) > 8192 || messageDigest([]byte(m.Header)) != m.HeaderSHA256 || r.Length < 1 || r.Length > store.HardwareRepairMaxRowBytes || r.Offset < m.FromOffset || r.Offset+int64(r.Length) > m.NextOffset || m.NextOffset > m.SnapshotSize {
		return empty, "", fmt.Errorf("invalid original manifest bounds")
	}
	f, err := os.Open(m.Path)
	if err != nil {
		return empty, "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return empty, "", err
	}
	if !st.Mode().IsRegular() || realtime.FileIdentity(m.Path, st) != m.FileID || st.Size() < m.NextOffset {
		return empty, "", fmt.Errorf("original file replaced or truncated")
	}
	header := make([]byte, len(m.Header))
	if _, err = io.ReadFull(f, header); err != nil || !bytes.Equal(header, []byte(m.Header)) {
		return empty, "", fmt.Errorf("original header changed")
	}
	raw := make([]byte, r.Length)
	if _, err = f.ReadAt(raw, r.Offset); err != nil {
		return empty, "", err
	}
	if messageDigest(raw) != r.SHA256 || raw[len(raw)-1] != '\n' {
		return empty, "", fmt.Errorf("original record checksum changed")
	}
	var output bytes.Buffer
	stats, err := zeek.Convert(bytes.NewReader(append(append([]byte(m.Header), raw...), '\n')), &output, zeek.Options{SensorID: m.Sensor, ControlledInterface: m.Interface, LogKind: kind, CaptureScope: m.CaptureScope, CollectorInstanceID: m.CaptureScope.CollectorInstanceID})
	if err != nil {
		return empty, "", err
	}
	if stats.Emitted != 1 {
		return empty, "original_record_not_decodable", nil
	}
	var event normalized.Event
	if err = json.Unmarshal(bytes.TrimSpace(output.Bytes()), &event); err != nil {
		return empty, "", err
	}
	at, err := time.Parse(time.RFC3339Nano, event.Timestamp)
	if err != nil {
		return empty, "original_timestamp_invalid", nil
	}
	if at.After(m.SnapshotAt) || at.Before(m.SnapshotAt.Add(-30*24*time.Hour)) {
		return empty, "outside_fixed_30_day_replay_window", nil
	}
	if event.Observer["capture_scope_issue"] != nil {
		return empty, "original_capture_scope_not_applicable", nil
	}
	event.RawRef["original_file_id"] = m.FileID
	event.RawRef["source_path"] = m.Path
	event.RawRef["start_offset"] = r.Offset
	event.RawRef["end_offset"] = r.Offset + int64(r.Length)
	return event, "", nil
}

func applyDHCPMessages(ctx context.Context, db *sql.DB, m dhcpMessageManifest, start, limit int) ([]store.HardwareRepairOutcome, error) {
	if start < 0 || start > len(m.Records) || limit < 1 || limit > 50 {
		return nil, fmt.Errorf("invalid replay batch")
	}
	end := min(start+limit, len(m.Records))
	events := []normalized.Event{}
	indices := []int{}
	out := []store.HardwareRepairOutcome{}
	size := 2
	for i := start; i < end; i++ {
		r := m.Records[i]
		e, reason, err := readDHCPMessage(m, r)
		if err != nil {
			return nil, err
		}
		encoded, err := json.Marshal(e)
		if err != nil {
			return nil, err
		}
		size += len(encoded) + 1
		if size > store.HardwareRepairMaxBatchBytes {
			if len(out) == 0 {
				return nil, fmt.Errorf("normalized record exceeds repair batch bound")
			}
			break
		}
		out = append(out, store.HardwareRepairOutcome{Index: i, SourceSHA256: r.SHA256, Status: "excluded", Reason: reason})
		if reason == "" {
			indices = append(indices, len(out)-1)
			events = append(events, e)
		}
	}
	if len(events) > 0 {
		var rows []store.HardwareRepairOutcome
		var err error
		if m.Schema == protocolReplaySchema {
			rows, err = store.ApplyRTSPOriginalReplay(ctx, db, m.Sensor, m.CIDRs, events)
		} else {
			rows, err = store.ApplyDHCPMessageReplay(ctx, db, m.Sensor, m.CIDRs, events)
		}
		if err != nil {
			return nil, err
		}
		for i, r := range rows {
			j := indices[i]
			r.Index = out[j].Index
			r.SourceSHA256 = out[j].SourceSHA256
			out[j] = r
		}
	}
	return out, nil
}

func runDHCPMessageApply(ctx context.Context, db *sql.DB, manifestPath, checkpointPath string, batch int, pause time.Duration) error {
	return runOriginalMessageApply(ctx, db, manifestPath, checkpointPath, batch, pause, dhcpMessageReplaySchema)
}
func runOriginalMessageApply(ctx context.Context, db *sql.DB, manifestPath, checkpointPath string, batch int, pause time.Duration, schema string) error {
	if checkpointPath == "" || filepath.Clean(manifestPath) == filepath.Clean(checkpointPath) || !discovery.HardwareProjectionEnabled() {
		return fmt.Errorf("original replay requires separate checkpoint and an already enabled hardware gate")
	}
	var m dhcpMessageManifest
	if err := readRepairJSON(manifestPath, &m); err != nil {
		return err
	}
	if m.Schema != schema || len(m.Records) > 5000 || m.NextOffset < m.FromOffset || m.NextOffset-m.FromOffset > 2<<20 {
		return fmt.Errorf("invalid original snapshot page")
	}
	if _, err := originalReplayKind(m); err != nil {
		return err
	}
	last := m.FromOffset
	for _, r := range m.Records {
		if r.Offset < last || r.Length < 1 || len(r.SHA256) != 64 {
			return fmt.Errorf("noncontiguous original record order")
		}
		last = r.Offset + int64(r.Length)
	}
	if last > m.NextOffset {
		return fmt.Errorf("original records exceed page")
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	var locked bool
	if err = conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1,0))`, "passive-hardware-repair:"+m.Sensor).Scan(&locked); err != nil {
		return err
	}
	if !locked {
		return fmt.Errorf("another repair owns sensor")
	}
	defer func() {
		c, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		conn.ExecContext(c, `SELECT pg_advisory_unlock(hashtextextended($1,0))`, "passive-hardware-repair:"+m.Sensor)
	}()
	state := repairCheckpoint{SchemaVersion: schema, ManifestSHA256: messageManifestHash(m), Total: len(m.Records), Complete: len(m.Records) == 0, Outcomes: []store.HardwareRepairOutcome{}, UpdatedAt: time.Now().UTC()}
	if err = readRepairJSON(checkpointPath, &state); errors.Is(err, os.ErrNotExist) {
		err = writeRepairJSON(checkpointPath, state, true)
	}
	if err != nil {
		return err
	}
	if state.SchemaVersion != schema || state.ManifestSHA256 != messageManifestHash(m) || state.Total != len(m.Records) || state.Next < 0 || state.Next > state.Total || len(state.Outcomes) != state.Next || state.Complete != (state.Next == state.Total) {
		return fmt.Errorf("original checkpoint mismatch")
	}
	for i, r := range state.Outcomes {
		if r.Index != i || r.SourceSHA256 != m.Records[i].SHA256 || (r.Status != "admitted" && r.Status != "excluded") {
			return fmt.Errorf("original checkpoint audit mismatch")
		}
	}
	save := func(s repairCheckpoint) error { return writeRepairJSON(checkpointPath, s, false) }
	apply := func(c context.Context, start, limit int) ([]store.HardwareRepairOutcome, error) {
		return applyDHCPMessages(c, db, m, start, limit)
	}
	for !state.Complete {
		c, cancel := context.WithTimeout(ctx, 2*time.Second)
		var busy bool
		err = db.QueryRowContext(c, `SELECT count(*)>=100 FROM (SELECT 1 FROM passive_hardware_dirty WHERE sensor_id=$1 LIMIT 100) q`, m.Sensor).Scan(&busy)
		cancel()
		if err != nil {
			return err
		}
		if busy {
			return fmt.Errorf("hardware queue busy; original checkpoint retained at %d/%d", state.Next, state.Total)
		}
		if err = advanceRepair(ctx, &state, batch, apply, save); err != nil {
			return err
		}
		if !state.Complete {
			timer := time.NewTimer(pause)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"mode": "original_replay_complete", "records": state.Total, "manifest_sha256": state.ManifestSHA256, "next_offset": m.NextOffset, "snapshot_size": m.SnapshotSize, "coverage": "one frozen source byte page; other pages and live cursor unchanged"})
}
