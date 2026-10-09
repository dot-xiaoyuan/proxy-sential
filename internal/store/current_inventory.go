package store

// Keep every candidate and signal; only duplicate raw event ID lists are reduced
// to references. Original normalized events and signal facts remain available.
func compactCurrentInventory(in IPDeviceInventory) IPDeviceInventory {
	out := in
	compactSignals := func(signals []DeviceSignal) []DeviceSignal {
		result := append([]DeviceSignal{}, signals...)
		for i := range result {
			if result[i].SeenCount < len(result[i].EventIDs) {
				result[i].SeenCount = len(result[i].EventIDs)
			}
			if len(result[i].EventIDs) > 16 {
				result[i].EventIDs = append([]string{}, result[i].EventIDs[:16]...)
			}
			if len(result[i].EventIDsSample) > 16 {
				result[i].EventIDsSample = append([]string{}, result[i].EventIDsSample[:16]...)
			}
		}
		return result
	}
	out.Signals = compactSignals(in.Signals)
	out.Devices = append([]ObservedDevice{}, in.Devices...)
	for i := range out.Devices {
		out.Devices[i].Signals = compactSignals(in.Devices[i].Signals)
	}
	return out
}
