package streamwal

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	headerSize           = 64
	sealPayloadSize      = 56
	sealSize             = headerSize + sealPayloadSize
	dataFrame       byte = 1
	sealFrame       byte = 2
	maxKindBytes         = 64
	maxIDBytes           = 256
	maxRecordBytes       = 4 << 20
	maxBatchBytes        = 8 << 20
	maxBatchRecords      = 1024
)

// Read/format guard, independent of runtime write budgets.
const maxLogBytes int64 = 64 << 30

var magic = [8]byte{'P', 'S', 'W', 'A', 'L', '0', '1', '\n'}

func chainSeal(prefix, seal [32]byte) [32]byte {
	var pair [64]byte
	copy(pair[:32], prefix[:])
	copy(pair[32:], seal[:])
	return sha256.Sum256(pair[:])
}

type frame struct {
	kind    byte
	lsn     uint64
	digest  [32]byte
	payload []byte
	length  int
}

func recordSize(r Record, o Options) (int, error) {
	if len(r.Kind) < 1 || len(r.Kind) > maxKindBytes || len(r.ID) < 1 || len(r.ID) > maxIDBytes || len(r.Payload) > o.MaxRecordBytes {
		return 0, ErrBounds
	}
	size := headerSize + 4 + len(r.Kind) + len(r.ID) + len(r.Payload)
	if size+sealSize > o.MaxBatchBytes || size > o.MaxQueuedBytes {
		return 0, ErrBounds
	}
	return size, nil
}

func encodeFrame(kind byte, lsn uint64, payload []byte) []byte {
	out := make([]byte, headerSize+len(payload))
	copy(out[:8], magic[:])
	out[8] = kind
	binary.BigEndian.PutUint64(out[16:24], lsn)
	binary.BigEndian.PutUint64(out[24:32], uint64(len(payload)))
	copy(out[headerSize:], payload)
	hash := sha256.New()
	hash.Write(out[:32])
	hash.Write(payload)
	copy(out[32:64], hash.Sum(nil))
	return out
}

func encodeGroup(batch []*request, first uint64, start int64) ([]byte, []Receipt) {
	size := sealSize
	for _, req := range batch {
		size += req.bytes
	}
	out := make([]byte, 0, size)
	receipts := make([]Receipt, 0, len(batch))
	for i, req := range batch {
		r := req.record
		payload := make([]byte, 4+len(r.Kind)+len(r.ID)+len(r.Payload))
		binary.BigEndian.PutUint16(payload[:2], uint16(len(r.Kind)))
		binary.BigEndian.PutUint16(payload[2:4], uint16(len(r.ID)))
		copy(payload[4:], r.Kind)
		copy(payload[4+len(r.Kind):], r.ID)
		copy(payload[4+len(r.Kind)+len(r.ID):], r.Payload)
		encoded := encodeFrame(dataFrame, first+uint64(i), payload)
		receipt := Receipt{LSN: first + uint64(i), Offset: start + int64(len(out)), Length: len(encoded)}
		copy(receipt.digest[:], encoded[32:64])
		receipts = append(receipts, receipt)
		out = append(out, encoded...)
	}
	groupHash := sha256.Sum256(out)
	sealPayload := make([]byte, sealPayloadSize)
	binary.BigEndian.PutUint64(sealPayload[:8], first)
	binary.BigEndian.PutUint64(sealPayload[8:16], uint64(len(batch)))
	binary.BigEndian.PutUint64(sealPayload[16:24], uint64(start))
	copy(sealPayload[24:], groupHash[:])
	seal := encodeFrame(sealFrame, first+uint64(len(batch))-1, sealPayload)
	for i := range receipts {
		receipts[i].sealOffset = start + int64(len(out))
		copy(receipts[i].sealDigest[:], seal[32:64])
	}
	return append(out, seal...), receipts
}

func readFrame(r io.ReaderAt, size, offset int64) (frame, error) {
	if offset < 0 || offset > size || size-offset < headerSize {
		return frame{}, ErrTail
	}
	header := make([]byte, headerSize)
	if _, err := r.ReadAt(header, offset); err != nil {
		return frame{}, err
	}
	if !bytes.Equal(header[:8], magic[:]) || !bytes.Equal(header[9:16], make([]byte, 7)) {
		return frame{}, ErrCorrupt
	}
	kind := header[8]
	n := binary.BigEndian.Uint64(header[24:32])
	if kind != dataFrame && kind != sealFrame || kind == sealFrame && n != sealPayloadSize || kind == dataFrame && (n < 6 || n > uint64(4+maxKindBytes+maxIDBytes+maxRecordBytes)) {
		return frame{}, ErrCorrupt
	}
	if n > uint64(size-offset-headerSize) {
		return frame{}, ErrTail
	}
	payload := make([]byte, int(n))
	if _, err := r.ReadAt(payload, offset+headerSize); err != nil {
		return frame{}, err
	}
	hash := sha256.New()
	hash.Write(header[:32])
	hash.Write(payload)
	if !bytes.Equal(hash.Sum(nil), header[32:64]) {
		return frame{}, ErrCorrupt
	}
	f := frame{kind: kind, lsn: binary.BigEndian.Uint64(header[16:24]), payload: payload, length: headerSize + int(n)}
	copy(f.digest[:], header[32:64])
	return f, nil
}

func decodeRecord(payload []byte) (Record, error) {
	if len(payload) < 4 {
		return Record{}, ErrCorrupt
	}
	kindLen, idLen := int(binary.BigEndian.Uint16(payload[:2])), int(binary.BigEndian.Uint16(payload[2:4]))
	if kindLen < 1 || kindLen > maxKindBytes || idLen < 1 || idLen > maxIDBytes || 4+kindLen+idLen > len(payload) {
		return Record{}, ErrCorrupt
	}
	r := Record{Kind: string(payload[4 : 4+kindLen]), ID: string(payload[4+kindLen : 4+kindLen+idLen]), Payload: payload[4+kindLen+idLen:]}
	if len(r.Payload) > maxRecordBytes {
		return Record{}, ErrCorrupt
	}
	return r, nil
}

func scan(r io.ReaderAt, size int64, _ Options, visit func(Entry) error) (Recovery, error) {
	var recovery Recovery
	if size < 0 || size > maxLogBytes {
		return recovery, ErrCapacity
	}
	var entries []Entry
	var offset int64
	groupBytes := 0
	groupHash := sha256.New()
	tail := func() (Recovery, error) {
		recovery.TailBytes = size - recovery.EndOffset
		return recovery, fmt.Errorf("%w at offset %d (%d bytes)", ErrTail, recovery.EndOffset, recovery.TailBytes)
	}
	for offset < size {
		f, err := readFrame(r, size, offset)
		if err == ErrTail {
			return tail()
		}
		if err != nil {
			return recovery, fmt.Errorf("frame offset %d: %w", offset, err)
		}
		if f.kind == dataFrame {
			if f.lsn != recovery.LastLSN+uint64(len(entries))+1 || len(entries) >= maxBatchRecords || groupBytes+f.length+sealSize > maxBatchBytes {
				return recovery, ErrCorrupt
			}
			record, err := decodeRecord(f.payload)
			if err != nil {
				return recovery, err
			}
			receipt := Receipt{LSN: f.lsn, Offset: offset, Length: f.length, digest: f.digest}
			entries = append(entries, Entry{Receipt: receipt, Record: record})
			groupBytes += f.length
			// Reconstruct only the small header; payload bytes are hashed exactly
			// as stored, never semantically re-encoded.
			header := make([]byte, headerSize)
			copy(header[:8], magic[:])
			header[8] = f.kind
			binary.BigEndian.PutUint64(header[16:24], f.lsn)
			binary.BigEndian.PutUint64(header[24:32], uint64(len(f.payload)))
			copy(header[32:], f.digest[:])
			groupHash.Write(header)
			groupHash.Write(f.payload)
		} else {
			if len(entries) == 0 || binary.BigEndian.Uint64(f.payload[:8]) != recovery.LastLSN+1 || binary.BigEndian.Uint64(f.payload[8:16]) != uint64(len(entries)) || binary.BigEndian.Uint64(f.payload[16:24]) != uint64(recovery.EndOffset) || f.lsn != recovery.LastLSN+uint64(len(entries)) || !bytes.Equal(f.payload[24:], groupHash.Sum(nil)) {
				return recovery, ErrCorrupt
			}
			for _, entry := range entries {
				entry.Receipt.sealOffset = offset
				entry.Receipt.sealDigest = f.digest
				if visit != nil {
					if err := visit(entry); err != nil {
						return recovery, err
					}
				}
			}
			recovery.LastLSN = f.lsn
			recovery.Records += uint64(len(entries))
			recovery.Groups++
			recovery.EndOffset = offset + int64(f.length)
			recovery.prefixDigest = chainSeal(recovery.prefixDigest, f.digest)
			entries = nil
			groupBytes = 0
			groupHash.Reset()
		}
		offset += int64(f.length)
	}
	if len(entries) > 0 {
		return tail()
	}
	return recovery, nil
}
