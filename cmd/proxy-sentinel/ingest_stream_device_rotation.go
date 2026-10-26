package main

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strconv"
	"strings"

	"proxy-sentinel/internal/realtime"
)

// The rotated .1 file is retained evidence. Verify every canceled chunk from
// the closed epoch before starting at the current file's zero offset.
func verifyClosedDeviceRotation(ctx context.Context, db *sql.DB, sourcePath, rotatedPath, retiredFileID string, retiredOffset int64, priorEpoch string) ([]zeekDiscardEntry, error) {
	if db == nil || rotatedPath != sourcePath+".1" || retiredFileID == "" || retiredOffset < 0 || priorEpoch == "" {
		return nil, errors.New("invalid device rotation proof")
	}
	file, err := os.Open(rotatedPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || realtime.FileIdentity(sourcePath, info) != retiredFileID || info.Size() < retiredOffset {
		return nil, errors.New("rotated device file does not match retired cursor")
	}
	scan, chunks, err := scanFileCutoverChunks(file, retiredOffset, info.Size(), false, 8<<20)
	if err != nil {
		return nil, err
	}
	if scan.Offset != info.Size() {
		return nil, errors.New("rotated device file has an incomplete record")
	}
	rows, err := db.QueryContext(ctx, `SELECT legacy_reference,content_sha256,unprocessed_records,unprocessed_bytes FROM stream_discard_manifest WHERE epoch=$1 AND source_kind='device-signals' AND source_path=$2 AND legacy_kind='stream_retirement_unread_chunk' ORDER BY legacy_reference`, priorEpoch, sourcePath)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type proof struct {
		hash           string
		records, bytes int64
	}
	audited := map[string]proof{}
	for rows.Next() {
		var ref, hash string
		var records, size int64
		if err := rows.Scan(&ref, &hash, &records, &size); err != nil {
			return nil, err
		}
		if !strings.HasPrefix(ref, retiredFileID+":") || len(hash) != 64 {
			return nil, errors.New("rotated device audit has a foreign chunk")
		}
		if _, exists := audited[ref]; exists {
			return nil, errors.New("duplicate rotated device audit chunk")
		}
		audited[ref] = proof{hash, records, size}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(audited) != len(chunks) {
		return nil, errors.New("rotated device audit chunk count changed")
	}
	entries := make([]zeekDiscardEntry, 0, len(chunks)+1)
	start := retiredOffset
	for _, chunk := range chunks {
		ref := retiredFileID + ":" + strconv.FormatInt(start, 10) + ":" + strconv.FormatInt(chunk.Offset, 10)
		old, ok := audited[ref]
		if !ok || old.hash != chunk.SHA256 || old.records != chunk.Records || old.bytes != chunk.Bytes {
			return nil, errors.New("rotated device audit content changed")
		}
		entries = append(entries, zeekDiscardEntry{LegacyKind: "rotated_closed_device_chunk", LegacyReference: ref, LegacyStatus: "cancelled_unprocessed", ContentSHA256: chunk.SHA256, UnprocessedRecords: chunk.Records, UnprocessedBytes: chunk.Bytes})
		start = chunk.Offset
	}
	stable, err := os.Stat(rotatedPath)
	if err != nil || !os.SameFile(info, stable) || stable.Size() != info.Size() {
		return nil, errors.New("rotated device file changed during verification")
	}
	entries = append(entries, zeekDiscardEntry{LegacyKind: "rotated_closed_device_file", LegacyReference: rotatedPath, LegacyStatus: "verified_retained", ContentSHA256: scan.SHA256})
	return entries, nil
}
