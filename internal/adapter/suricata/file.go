package suricata

import (
	"fmt"
	"io"
	"os"
)

func ConvertFiles(inputPath, outputPath string, opts Options) (Stats, error) {
	input, closeInput, err := openInput(inputPath)
	if err != nil {
		return Stats{}, err
	}
	defer closeInput()

	output, closeOutput, err := openOutput(outputPath)
	if err != nil {
		return Stats{}, err
	}
	defer closeOutput()

	return Convert(input, output, opts)
}

func openInput(path string) (io.Reader, func() error, error) {
	if path == "-" {
		return os.Stdin, func() error { return nil }, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open input: %w", err)
	}
	return file, file.Close, nil
}

func openOutput(path string) (io.Writer, func() error, error) {
	if path == "-" {
		return os.Stdout, func() error { return nil }, nil
	}
	file, err := os.Create(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open output: %w", err)
	}
	return file, file.Close, nil
}
