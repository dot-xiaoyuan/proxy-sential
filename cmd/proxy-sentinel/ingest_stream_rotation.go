package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// verifyClosedRotationArchive anchors the old Zeek archive to the immutable
// unread range in a closed epoch. The old tail and the new file prefix then
// become separate cancelled ranges in the next epoch's manifest.
func verifyClosedRotationArchive(ctx context.Context, db *sql.DB, sourcePath, archivePath, oldFileID string, closedOffset int64, priorEpoch string) ([]zeekDiscardEntry, error) {
	if oldFileID == "" || closedOffset < 0 || priorEpoch == "" || !filepath.IsAbs(archivePath) || filepath.Clean(archivePath) != archivePath {
		return nil, errors.New("invalid rotation archive reference")
	}
	logsDir := filepath.Dir(filepath.Dir(sourcePath))
	rel, err := filepath.Rel(logsDir, archivePath)
	if err != nil || strings.HasPrefix(rel, "..") || strings.Contains(rel, string(filepath.Separator)+".."+string(filepath.Separator)) || strings.HasPrefix(rel, "current"+string(filepath.Separator)) || !strings.HasPrefix(filepath.Base(rel), "device_dhcp_binding.") || !strings.HasSuffix(rel, ".log.gz") {
		return nil, errors.New("rotation archive is outside dated Zeek logs")
	}
	realLogs, err := filepath.EvalSymlinks(logsDir)
	if err != nil {
		return nil, err
	}
	realArchive, err := filepath.EvalSymlinks(archivePath)
	if err != nil {
		return nil, err
	}
	realRel, err := filepath.Rel(realLogs, realArchive)
	if err != nil || strings.HasPrefix(realRel, "..") || strings.HasPrefix(realRel, "current"+string(filepath.Separator)) {
		return nil, errors.New("rotation archive resolves outside dated Zeek logs")
	}
	var unreadRef, unreadHash string
	rows, err := db.QueryContext(ctx, `SELECT legacy_reference,content_sha256 FROM stream_discard_manifest WHERE epoch=$1 AND source_kind='zeek-dhcp-binding' AND source_path=$2 AND legacy_kind='unread_binding_file' LIMIT 2`, priorEpoch, sourcePath)
	if err != nil {
		return nil, fmt.Errorf("closed epoch unread anchor: %w", err)
	}
	defer rows.Close()
	anchors := 0
	for rows.Next() {
		if err := rows.Scan(&unreadRef, &unreadHash); err != nil {
			return nil, err
		}
		anchors++
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if anchors != 1 {
		return nil, errors.New("closed epoch has no unique unread anchor")
	}
	if !strings.HasPrefix(unreadRef, sourcePath+":") || len(unreadHash) != 64 {
		return nil, errors.New("closed epoch unread anchor does not match source")
	}
	ranges := strings.Split(strings.TrimPrefix(unreadRef, sourcePath+":"), ":")
	if len(ranges) != 2 {
		return nil, errors.New("invalid closed epoch unread range")
	}
	start, err := strconv.ParseInt(ranges[0], 10, 64)
	if err != nil || start < 0 || start >= closedOffset || ranges[1] != strconv.FormatInt(closedOffset, 10) {
		return nil, errors.New("closed epoch unread range is not adjacent to retirement cursor")
	}
	f, err := os.Open(archivePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<20 {
		return nil, errors.New("rotation archive is not a bounded regular file")
	}
	compressed, err := io.ReadAll(io.LimitReader(f, (64<<20)+1))
	if err != nil || len(compressed) > 64<<20 {
		return nil, errors.New("rotation archive exceeds compressed bound")
	}
	gz, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, err
	}
	decoded, err := io.ReadAll(io.LimitReader(gz, (256<<20)+1))
	closeErr := gz.Close()
	if err != nil || closeErr != nil || len(decoded) > 256<<20 {
		return nil, errors.New("rotation archive failed bounded gzip validation")
	}
	current, err := os.Stat(archivePath)
	if err != nil || !os.SameFile(info, current) || current.Size() != info.Size() {
		return nil, errors.New("rotation archive changed during audit")
	}
	if int64(len(decoded)) < closedOffset || hashRotationBytes(decoded[start:closedOffset]) != unreadHash || (len(decoded) > 0 && decoded[len(decoded)-1] != '\n') {
		return nil, errors.New("rotation archive does not match the closed epoch's final unread bytes")
	}
	tail := decoded[closedOffset:]
	var records int64
	for _, line := range bytes.Split(tail, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) > 0 && line[0] != '#' {
			records++
		}
	}
	return []zeekDiscardEntry{
		{LegacyKind: "rotated_closed_stream_tail", LegacyReference: oldFileID + ":" + strconv.FormatInt(closedOffset, 10) + ":" + strconv.Itoa(len(decoded)), LegacyStatus: "cancelled_unprocessed", ContentSHA256: hashRotationBytes(tail), UnprocessedRecords: records, UnprocessedBytes: int64(len(tail))},
		{LegacyKind: "rotation_archive", LegacyReference: archivePath, LegacyStatus: "verified_archive", ContentSHA256: hashRotationBytes(compressed)},
	}, nil
}

func hashRotationBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
