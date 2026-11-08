package store

import (
	"encoding/json"
	"strings"
)

func registrationMAC(endpointID string) string {
	if !strings.HasPrefix(endpointID, "mac:") {
		return ""
	}
	mac := validPassiveMAC(strings.TrimPrefix(endpointID, "mac:"))
	if endpointID != "mac:"+mac {
		return ""
	}
	return mac
}

func registrationDetailsDocument(update EndpointRegistrationUpdate) []byte {
	if update.RegistrationDetails == nil {
		return nil
	}
	details := *update.RegistrationDetails
	details.Name = strings.TrimSpace(details.Name)
	details.DeviceType = strings.TrimSpace(details.DeviceType)
	details.Manufacturer = strings.TrimSpace(details.Manufacturer)
	details.Model = strings.TrimSpace(details.Model)
	details.SerialNumber = strings.TrimSpace(details.SerialNumber)
	details.RegisteredIP = strings.TrimSpace(details.RegisteredIP)
	details.Location = strings.TrimSpace(details.Location)
	raw, _ := json.Marshal(struct {
		EndpointRegistrationDetails
		Source    string `json:"source"`
		UpdatedAt string `json:"updated_at"`
	}{EndpointRegistrationDetails: details, Source: "local", UpdatedAt: update.RegistrationUpdatedAt})
	return raw
}
