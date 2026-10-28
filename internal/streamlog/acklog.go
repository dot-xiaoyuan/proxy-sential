package streamlog

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

// New segments keep lane transitions in an append-only, fsynced file. Its
// empty inode is prepared before the source cursor commits; that cursor's
// directory sync seals the entry. An attempted marker is then file-synced
// before any external write. Old segments retain the atomic state format.
func (j *Journal) prepareEmptyAckLog(id string) error {
	path := j.path(id, ".acklog")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if os.IsExist(err) {
		f, err = os.OpenFile(path, os.O_WRONLY, 0)
	}
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil || info.Size() != 0 {
		_ = f.Close()
		if err != nil {
			return err
		}
		return ErrContentConflict
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func (j *Journal) createAckLogWithRecord(id string, lane Lane, status Status) error {
	f, err := os.OpenFile(j.path(id, ".acklog"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err = f.WriteString(ackRecord(id, lane, status)); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return syncDir(j.dir)
}

func ackRecord(id string, lane Lane, status Status) string {
	text := string(lane) + "," + string(status)
	sum := sha256.Sum256([]byte(id + "\x00" + text))
	return text + "," + hex.EncodeToString(sum[:]) + "\n"
}

func parseAckRecord(id, line string) (Lane, Status, error) {
	parts := strings.Split(line, ",")
	if len(parts) != 3 {
		return "", "", ErrContentConflict
	}
	lane, status := Lane(parts[0]), Status(parts[1])
	if !validLane(lane) || status != Pending && status != Attempted && status != Acked {
		return "", "", ErrContentConflict
	}
	if strings.TrimSpace(ackRecord(id, lane, status)) != line {
		return "", "", ErrContentConflict
	}
	return lane, status, nil
}

// applyAckLog overlays durable transitions and returns the last valid byte
// offset. An unterminated tail may be the last write interrupted by a crash;
// it is discarded before the next append under the segment's process lock.
func (j *Journal) applyAckLog(id string, state *State) (int64, error) {
	f, err := os.Open(j.path(id, ".acklog"))
	if err != nil {
		return 0, err
	}
	defer f.Close()
	reader := bufio.NewReader(f)
	var offset int64
	for {
		line, readErr := reader.ReadString('\n')
		if readErr == io.EOF {
			return offset, nil
		}
		if readErr != nil {
			return 0, readErr
		}
		lane, status, err := parseAckRecord(id, strings.TrimSuffix(line, "\n"))
		if err != nil {
			return 0, fmt.Errorf("stream segment %s acknowledgement log: %w", id, err)
		}
		if state.Acks[lane] == NotApplicable || state.Acks[lane] == "" {
			return 0, ErrContentConflict
		}
		state.Acks[lane] = status
		offset += int64(len(line))
	}
}

func (j *Journal) appendAck(id string, lane Lane, status Status, entrySealed bool) error {
	// The caller holds the segment lock. Validate and truncate only an
	// incomplete final write; complete corrupt records stop the source.
	state := State{Acks: map[Lane]Status{Archive: Pending, Search: Pending, Projection: Pending, RiskFeatures: Pending}}
	valid, err := j.applyAckLog(id, &state)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(j.path(id, ".acklog"), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size() > valid {
		if err := f.Truncate(valid); err != nil {
			return err
		}
	}
	if _, err := f.WriteString(ackRecord(id, lane, status)); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	// An empty file left by a crash during the first record may not yet have
	// a durable directory entry. Seal it before permitting a sink write.
	if !entrySealed {
		return syncDir(j.dir)
	}
	return nil
}
