package fingerprint

// userAgentDeviceHints maps explicit client browser tokens to a device class.
// Confidence stays at clue level: a user agent is self-reported by the client.
var userAgentDeviceHints = []struct {
	marker      string
	deviceType  string
	description string
	confidence  float64
}{
	{"iphone", "mobile", "iPhone 浏览器", .78},
	{"ipad", "tablet", "iPad 浏览器", .78},
	{"ipod", "mobile", "iPod 浏览器", .70},
	{"macintosh", "desktop", "Mac 浏览器", .72},
	{"windows nt", "desktop", "Windows 浏览器", .70},
	{"android", "mobile", "Android 浏览器", .72},
}
