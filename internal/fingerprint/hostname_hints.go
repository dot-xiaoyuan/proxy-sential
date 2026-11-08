package fingerprint

// hostnameDeviceHints lists explicit, device-reported hostname prefixes that
// identify a device class. Confidence stays at clue level; the page must not
// present these as confirmed types.
var hostnameDeviceHints = []struct {
	prefix      string
	deviceType  string
	description string
	confidence  float64
}{
	{"laptop-", "desktop", "Windows 默认笔记本主机名", .72},
	{"desktop-", "desktop", "Windows 默认台式机主机名", .72},
	{"lenovo-pc", "desktop", "Lenovo PC 主机名", .75},
	{"iqoo-pad", "tablet", "iQOO 平板型号主机名", .78},
	{"iqoo-", "mobile", "iQOO 手机型号主机名", .78},
	{"iphone", "mobile", "iPhone 默认主机名", .74},
	{"ipad", "tablet", "iPad 默认主机名", .74},
	{"ipod", "mobile", "iPod 默认主机名", .7},
	{"macbook", "desktop", "MacBook 默认主机名", .72},
	{"imac", "desktop", "iMac 默认主机名", .72},
	{"appletv", "media_device", "Apple TV 默认主机名", .7},
}
