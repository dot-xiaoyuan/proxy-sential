package appdomain

import "time"

const applicationScanBatchSize = 5000

// ScanWindow bounds source aggregation independently of the immutable job range.
// Old jobs resume from their existing event cursor without replaying empty time.
func (j Job) ScanWindow() Scan {
	from := j.ScanFrom
	if from.IsZero() {
		from = j.From
		if at, err := time.Parse(time.RFC3339Nano, j.After.Timestamp); err == nil && at.After(from) {
			from = at
		}
	}
	seconds := j.ScanSeconds
	if seconds <= 0 {
		seconds = 600
	}
	to := j.ScanTo
	if to.IsZero() {
		to = from.Add(time.Duration(seconds) * time.Second)
	}
	if to.After(j.To) {
		to = j.To
	}
	return Scan{From: from, To: to, After: j.After, Limit: applicationScanBatchSize}
}

// FinishScanWindow is persisted with the prepared batch, never before its results.
func (j *Job) FinishScanWindow(q Scan, count int) {
	j.ScanFrom = q.From
	j.ScanTo = q.To
	if count < q.Limit {
		j.ScanFrom = q.To
		j.ScanTo = time.Time{}
		if !q.To.Before(j.To) {
			j.Status = "completed"
		}
	}
}

// ShrinkScanWindow changes only the retry range, never acknowledged progress.
func (j *Job) ShrinkScanWindow() bool {
	q := j.ScanWindow()
	from := q.From
	if at, err := time.Parse(time.RFC3339Nano, j.After.Timestamp); err == nil && at.After(from) {
		from = at
	}
	remaining := q.To.Sub(from)
	if remaining <= time.Second {
		return false
	}
	seconds := int(remaining/time.Second) / 2
	if seconds < 1 {
		seconds = 1
	}
	j.ScanFrom = from
	j.ScanSeconds = seconds
	j.ScanTo = from.Add(time.Duration(seconds) * time.Second)
	return true
}
