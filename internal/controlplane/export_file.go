package controlplane

import (
	"bytes"
	"io"
	"path/filepath"
)

func exportFilePath(dir string, job ExportJob) string {
	ext := ".csv"
	if job.Kind == "unknown-domains" {
		ext = ".jsonl"
	}
	return filepath.Join(dir, job.ExportID+ext)
}

type exportLineWriter struct {
	io.Writer
	rows int
}

func (w *exportLineWriter) Write(data []byte) (int, error) {
	n, err := w.Writer.Write(data)
	w.rows += bytes.Count(data[:n], []byte{'\n'})
	return n, err
}
