package normalized

// HardwareClassificationVersion is additive: risk consumers must not derive a
// risk decision from these asset-only fields. The feature is disabled by default.
const HardwareClassificationVersion = "passive-hardware/v2"

// PassiveHardwarePayload documents the bounded response-only adapter contract.
// It contains extracted values, never a second copy of a packet or credentials.
// RawRef on Event remains the authoritative source reference. A response IP
// alone does not establish ownership; consumers require scoped event-time L2.
type PassiveHardwarePayload struct {
	IsResponse        bool              `json:"is_response"`
	ResponseSourceIP  string            `json:"response_source_ip"`
	ParserVersion     string            `json:"parser_version"`
	ProductModel      string            `json:"product_model,omitempty"`
	Manufacturer      string            `json:"manufacturer,omitempty"`
	SystemDescription string            `json:"system_description,omitempty"`
	SystemObjectID    string            `json:"system_object_id,omitempty"`
	SNMPVarbinds      map[string]string `json:"snmp_varbinds,omitempty"`
	BACnetVendorID    string            `json:"bacnet_vendor_id,omitempty"`
	BACnetDeviceID    string            `json:"bacnet_device_id,omitempty"`
	BACnetObjectName  string            `json:"bacnet_object_name,omitempty"`
	ModbusVendorName  string            `json:"modbus_vendor_name,omitempty"`
	ModbusProductCode string            `json:"modbus_product_code,omitempty"`
	ModbusRevision    string            `json:"modbus_revision,omitempty"`
}

const HardwareMaxValueBytes = 4096
const HardwareMaxVarbinds = 64
