package devicesignal

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"proxy-sentinel/internal/sharedaccess"
)

const captureCoverageTailBytes = 64 << 20

var errCaptureOutputIncomplete = errors.New("capture output ends in an incomplete JSONL record")

type captureCoverageCheckpoint struct {
	Schema     string                  `json:"schema"`
	Sensor     string                  `json:"sensor"`
	Instance   string                  `json:"instance"`
	Coverage   sharedaccess.CoverageV2 `json:"coverage"`
	RecordHash string                  `json:"record_hash"`
}

func captureCoverageCheckpointPath(output string) string {
	return output + ".coverage-checkpoint.json"
}

func captureCoverageHash(sensor, instance string, coverage sharedaccess.CoverageV2) string {
	raw, _ := json.Marshal(struct {
		Sensor   string                  `json:"sensor"`
		Instance string                  `json:"instance"`
		Coverage sharedaccess.CoverageV2 `json:"coverage"`
	}{sensor, instance, coverage})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// The JSONL coverage row is synced before this checkpoint. A stale checkpoint
// is conservative; the next start also checks the readable output tail.
func saveCaptureCoverageCheckpoint(output, sensor, instance string, coverage sharedaccess.CoverageV2) error {
	checkpoint := captureCoverageCheckpoint{
		Schema: "capture-coverage-checkpoint/v1", Sensor: sensor, Instance: instance,
		Coverage: coverage, RecordHash: captureCoverageHash(sensor, instance, coverage),
	}
	path := captureCoverageCheckpointPath(output)
	file, err := os.CreateTemp(filepath.Dir(path), ".capture-coverage-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err := file.Chmod(0640); err != nil {
		file.Close()
		return err
	}
	if err := json.NewEncoder(file).Encode(checkpoint); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func loadCaptureCoverageCheckpoint(output, sensor, instance string) (sharedaccess.CoverageV2, bool, error) {
	raw, err := os.ReadFile(captureCoverageCheckpointPath(output))
	if os.IsNotExist(err) {
		return sharedaccess.CoverageV2{}, false, nil
	}
	if err != nil {
		return sharedaccess.CoverageV2{}, false, err
	}
	var checkpoint captureCoverageCheckpoint
	if err := json.Unmarshal(raw, &checkpoint); err != nil {
		return sharedaccess.CoverageV2{}, false, err
	}
	if checkpoint.Schema != "capture-coverage-checkpoint/v1" || checkpoint.Sensor != sensor || checkpoint.Instance != instance ||
		!validCaptureCoverage(checkpoint.Coverage) || checkpoint.RecordHash != captureCoverageHash(sensor, instance, checkpoint.Coverage) {
		return sharedaccess.CoverageV2{}, false, fmt.Errorf("capture coverage checkpoint is invalid or belongs to another instance")
	}
	return checkpoint.Coverage, true, nil
}

func validCaptureCoverage(coverage sharedaccess.CoverageV2) bool {
	return coverage.SchemaVersion == "capture-coverage/v2" && !coverage.From.IsZero() && coverage.To.After(coverage.From)
}

// Search a bounded tail of the live file and, if needed, the two newest plain
// rotated files. Supports both .1 logrotate names and timestamped rotations.
// Full raw-chain scans would pause capture for too long.
func lastPersistedCaptureCoverage(output, sensor, instance string) (sharedaccess.CoverageV2, bool, error) {
	checkpoint, checkpointFound, checkpointErr := loadCaptureCoverageCheckpoint(output, sensor, instance)
	files := []string{output}
	type candidate struct {
		path string
		mod  time.Time
	}
	var rotated []candidate
	for _, pattern := range []string{output + "-[0-9]*", output + ".[0-9]*"} {
		paths, err := filepath.Glob(pattern)
		if err != nil {
			return sharedaccess.CoverageV2{}, false, err
		}
		for _, path := range paths {
			if !plainCaptureRotation(output, path) {
				continue
			}
			info, err := os.Stat(path)
			if err != nil {
				return sharedaccess.CoverageV2{}, false, err
			}
			rotated = append(rotated, candidate{path: path, mod: info.ModTime()})
		}
	}
	sort.Slice(rotated, func(i, j int) bool {
		if rotated[i].mod.Equal(rotated[j].mod) {
			return rotated[i].path > rotated[j].path
		}
		return rotated[i].mod.After(rotated[j].mod)
	})
	for i := 0; i < len(rotated) && i < 2; i++ {
		files = append(files, rotated[i].path)
	}
	best, found := checkpoint, checkpointFound
	for _, path := range files {
		coverage, ok, err := readCaptureCoverageTail(path, sensor, instance)
		if err != nil {
			return sharedaccess.CoverageV2{}, false, err
		}
		if ok && (!found || coverage.To.After(best.To)) {
			best, found = coverage, true
		}
		if ok && path == output {
			break
		}
	}
	if !found && checkpointErr != nil {
		return sharedaccess.CoverageV2{}, false, checkpointErr
	}
	return best, found, nil
}

func plainCaptureRotation(output, path string) bool {
	suffix := strings.TrimPrefix(path, output)
	if strings.HasPrefix(suffix, ".") && len(suffix) > 1 {
		_, err := strconv.Atoi(suffix[1:])
		return err == nil
	}
	if strings.HasPrefix(suffix, "-") && len(suffix) == len("-20060102-150405") {
		_, err := time.Parse("-20060102-150405", suffix)
		return err == nil
	}
	return false
}

func readCaptureCoverageTail(path, sensor, instance string) (sharedaccess.CoverageV2, bool, error) {
	return readCaptureCoverageTailWithSync(path, sensor, instance, (*os.File).Sync)
}

func readCaptureCoverageTailWithSync(path, sensor, instance string, syncFile func(*os.File) error) (sharedaccess.CoverageV2, bool, error) {
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return sharedaccess.CoverageV2{}, false, nil
	}
	if err != nil {
		return sharedaccess.CoverageV2{}, false, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return sharedaccess.CoverageV2{}, false, err
	}
	if info.Size() == 0 {
		return sharedaccess.CoverageV2{}, false, nil
	}
	// A complete row can still be only in page cache if the previous writer's
	// Encode succeeded but Sync failed. Fix the read boundary at the size seen
	// before this call, then confirm those bytes are durable before accepting a
	// tail row as the recovery watermark.
	if err := syncFile(file); err != nil {
		return sharedaccess.CoverageV2{}, false, fmt.Errorf("sync capture output before recovery tail read %s: %w", path, err)
	}
	start := max(int64(0), info.Size()-captureCoverageTailBytes)
	data := make([]byte, int(info.Size()-start))
	if _, err := file.ReadAt(data, start); err != nil && err != io.EOF {
		return sharedaccess.CoverageV2{}, false, err
	}
	if data[len(data)-1] != '\n' {
		return sharedaccess.CoverageV2{}, false, fmt.Errorf("%w: %s", errCaptureOutputIncomplete, path)
	}
	if start > 0 {
		firstNewline := bytes.IndexByte(data, '\n')
		if firstNewline < 0 {
			return sharedaccess.CoverageV2{}, false, nil
		}
		data = data[firstNewline+1:]
	}
	lines := bytes.Split(data, []byte{'\n'})
	for i := len(lines) - 1; i >= 0; i-- {
		if !bytes.Contains(lines[i], []byte(`"source_event_type":"capture_coverage"`)) {
			continue
		}
		var row struct {
			Source          string `json:"source"`
			SourceEventType string `json:"source_event_type"`
			Observer        struct {
				Sensor   string `json:"sensor_id"`
				Instance string `json:"collector_instance_id"`
			} `json:"observer"`
			Payload struct {
				Coverage sharedaccess.CoverageV2 `json:"capture_coverage"`
			} `json:"payload"`
		}
		if err := json.Unmarshal(lines[i], &row); err != nil {
			continue
		}
		if row.Source == "packet-sidecar" && row.SourceEventType == "capture_coverage" && row.Observer.Sensor == sensor && row.Observer.Instance == instance && validCaptureCoverage(row.Payload.Coverage) {
			return row.Payload.Coverage, true, nil
		}
	}
	return sharedaccess.CoverageV2{}, false, nil
}

func captureCoverageGap(previous sharedaccess.CoverageV2, start time.Time) (sharedaccess.CoverageV2, bool) {
	if !start.After(previous.To) {
		return sharedaccess.CoverageV2{}, false
	}
	return sharedaccess.CoverageV2{SchemaVersion: "capture-coverage/v2", From: previous.To, To: start, KernelStatsKnown: false, Stopped: true}, true
}

// A failed lookup cannot identify the previous capture boundary. Persist the
// measurable socket startup interval anyway, including its reset counters.
// It remains incomplete and does not claim anything about time before bind.
func routerStartupCoverage(boundAt, start time.Time, previous sharedaccess.CoverageV2, previousKnown bool, priorErr error, received, dropped uint32) (sharedaccess.CoverageV2, bool) {
	if previousKnown && priorErr == nil {
		if gap, ok := captureCoverageGap(previous, start); ok {
			gap.Received, gap.Dropped = uint64(received), uint64(dropped)
			return gap, true
		}
	}
	if !start.After(boundAt) {
		boundAt = start.Add(-time.Nanosecond)
	}
	return sharedaccess.CoverageV2{
		SchemaVersion: "capture-coverage/v2", From: boundAt, To: start,
		KernelStatsKnown: false, Received: uint64(received), Dropped: uint64(dropped), Stopped: true,
	}, false
}
