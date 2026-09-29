// Package actionreceipt validates the connector completion contract. Transport
// acceptance is not evidence of an action's completion.
package actionreceipt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

func Completed(body []byte, revoke bool) (string, error) {
	if len(body) == 0 || len(body) > 1<<20 {
		return "", fmt.Errorf("invalid action receipt size")
	}
	var receipt struct {
		ID     string `json:"action_id"`
		Status string `json:"status"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&receipt); err != nil {
		return "", fmt.Errorf("invalid action receipt")
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return "", fmt.Errorf("trailing action receipt")
	}
	if receipt.ID == "" || strings.TrimSpace(receipt.ID) != receipt.ID || len(receipt.ID) > 256 {
		return "", fmt.Errorf("action receipt requires remote action ID")
	}
	if receipt.Status != "completed" && !(receipt.Status == "succeeded" && !revoke) && !(receipt.Status == "revoked" && revoke) {
		return "", fmt.Errorf("action completion not confirmed")
	}
	return receipt.ID, nil
}
