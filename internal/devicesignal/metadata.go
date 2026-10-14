package devicesignal

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
)

// metadataTailBytes bounds how far the observed metadata scan reads back from
// the end of the signal file. Records are appended continuously, so the newest
// capture interface is always inside the tail.
const metadataTailBytes = 64 << 10

// ObservedInterface reports the capture interface recorded by the newest
// device-signal record. An ingest service only reads the normalized file, so
// this is how it can register the interface the capture process actually owns
// instead of guessing a default NIC name. It returns "" when the file is
// missing, empty, or holds no readable record.
func ObservedInterface(path string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Size() == 0 {
		return ""
	}
	start := int64(0)
	if info.Size() > metadataTailBytes {
		start = info.Size() - metadataTailBytes
	}
	if _, err := file.Seek(start, io.SeekStart); err != nil {
		return ""
	}
	reader := bufio.NewReaderSize(file, metadataTailBytes)
	if start > 0 {
		// Drop the partial record the seek cut in half.
		if _, err := reader.ReadString('\n'); err != nil && !errors.Is(err, io.EOF) {
			return ""
		}
	}
	observed := ""
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			var record struct {
				Observer struct {
					Interface string `json:"interface"`
				} `json:"observer"`
			}
			if json.Unmarshal(line, &record) == nil {
				if name := strings.TrimSpace(record.Observer.Interface); name != "" {
					observed = name
				}
			}
		}
		if err != nil {
			return observed
		}
	}
}
