package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"proxy-sentinel/internal/legacygateway"
	"strings"
	"syscall"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	addr := flag.String("addr", ":8091", "listen address")
	target := flag.String("target-url", os.Getenv("LEGACY_GATEWAY_URL"), "legacy gateway action URL")
	secretFile := flag.String("connector-secret-file", os.Getenv("PROXY_SENTINEL_CONNECTOR_SECRET_FILE"), "file containing connector HMAC secret")
	targetTokenFile := flag.String("target-token-file", os.Getenv("LEGACY_GATEWAY_TOKEN_FILE"), "optional legacy gateway token file")
	state := flag.String("state", "data/legacy-northbound-state.json", "idempotency state file")
	flag.Parse()
	secret, err := readSecret(*secretFile, true)
	if err != nil {
		return err
	}
	token, err := readSecret(*targetTokenFile, false)
	if err != nil {
		return err
	}
	handler, err := legacygateway.New(legacygateway.Options{Secret: secret, TargetURL: *target, TargetToken: token, StatePath: *state})
	if err != nil {
		return err
	}
	server := &http.Server{Addr: *addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	result := make(chan error, 1)
	go func() { result <- server.ListenAndServe() }()
	select {
	case err := <-result:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	}
}
func readSecret(path string, required bool) (string, error) {
	if path == "" {
		if required {
			return "", fmt.Errorf("secret file is required")
		}
		return "", nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(data))
	if required && value == "" {
		return "", fmt.Errorf("secret file is empty")
	}
	return value, nil
}
