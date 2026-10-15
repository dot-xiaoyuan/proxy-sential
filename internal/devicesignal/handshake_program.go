package devicesignal

// bpfInsn is one classic BPF instruction. The table is platform neutral so the program can be
// verified on any development host; only the socket attach is Linux specific.
type bpfInsn struct {
	Code uint16
	Jt   uint8
	Jf   uint8
	K    uint32
}

// handshakeProgram is generated with libpcap from:
// (ip and tcp and P) or (vlan and ip and tcp and P), where P is (dst port 443 or dst port 80)
// and the payload begins with a TLS ClientHello record or an HTTP request method. The accept
// return is bounded to 1024 bytes: enough for the ClientHello server_name and ALPN extensions
// and the HTTP request headers, while bulk application payload stays in the kernel.
var handshakeProgram = []bpfInsn{
	{Code: 40, Jt: 0, Jf: 0, K: 12},
	{Code: 21, Jt: 0, Jf: 23, K: 2048},
	{Code: 48, Jt: 0, Jf: 0, K: 23},
	{Code: 21, Jt: 0, Jf: 53, K: 6},
	{Code: 40, Jt: 0, Jf: 0, K: 20},
	{Code: 69, Jt: 51, Jf: 0, K: 8191},
	{Code: 177, Jt: 0, Jf: 0, K: 14},
	{Code: 72, Jt: 0, Jf: 0, K: 16},
	{Code: 21, Jt: 1, Jf: 0, K: 443},
	{Code: 21, Jt: 0, Jf: 47, K: 80},
	{Code: 80, Jt: 0, Jf: 0, K: 26},
	{Code: 84, Jt: 0, Jf: 0, K: 240},
	{Code: 116, Jt: 0, Jf: 0, K: 2},
	{Code: 12, Jt: 0, Jf: 0, K: 0},
	{Code: 7, Jt: 0, Jf: 0, K: 0},
	{Code: 80, Jt: 0, Jf: 0, K: 14},
	{Code: 21, Jt: 39, Jf: 0, K: 22},
	{Code: 177, Jt: 0, Jf: 0, K: 14},
	{Code: 80, Jt: 0, Jf: 0, K: 26},
	{Code: 84, Jt: 0, Jf: 0, K: 240},
	{Code: 116, Jt: 0, Jf: 0, K: 2},
	{Code: 12, Jt: 0, Jf: 0, K: 0},
	{Code: 7, Jt: 0, Jf: 0, K: 0},
	{Code: 64, Jt: 0, Jf: 0, K: 14},
	{Code: 21, Jt: 31, Jf: 28, K: 1195725856},
	{Code: 21, Jt: 2, Jf: 0, K: 33024},
	{Code: 21, Jt: 1, Jf: 0, K: 34984},
	{Code: 21, Jt: 0, Jf: 29, K: 37120},
	{Code: 40, Jt: 0, Jf: 0, K: 16},
	{Code: 21, Jt: 0, Jf: 27, K: 2048},
	{Code: 48, Jt: 0, Jf: 0, K: 27},
	{Code: 21, Jt: 0, Jf: 25, K: 6},
	{Code: 40, Jt: 0, Jf: 0, K: 24},
	{Code: 69, Jt: 23, Jf: 0, K: 8191},
	{Code: 177, Jt: 0, Jf: 0, K: 18},
	{Code: 72, Jt: 0, Jf: 0, K: 20},
	{Code: 21, Jt: 1, Jf: 0, K: 443},
	{Code: 21, Jt: 0, Jf: 19, K: 80},
	{Code: 80, Jt: 0, Jf: 0, K: 30},
	{Code: 84, Jt: 0, Jf: 0, K: 240},
	{Code: 116, Jt: 0, Jf: 0, K: 2},
	{Code: 12, Jt: 0, Jf: 0, K: 0},
	{Code: 7, Jt: 0, Jf: 0, K: 0},
	{Code: 80, Jt: 0, Jf: 0, K: 18},
	{Code: 21, Jt: 11, Jf: 0, K: 22},
	{Code: 177, Jt: 0, Jf: 0, K: 18},
	{Code: 80, Jt: 0, Jf: 0, K: 30},
	{Code: 84, Jt: 0, Jf: 0, K: 240},
	{Code: 116, Jt: 0, Jf: 0, K: 2},
	{Code: 12, Jt: 0, Jf: 0, K: 0},
	{Code: 7, Jt: 0, Jf: 0, K: 0},
	{Code: 64, Jt: 0, Jf: 0, K: 18},
	{Code: 21, Jt: 3, Jf: 0, K: 1195725856},
	{Code: 21, Jt: 2, Jf: 0, K: 1347375956},
	{Code: 21, Jt: 1, Jf: 0, K: 1212498244},
	{Code: 21, Jt: 0, Jf: 1, K: 1347769376},
	{Code: 6, Jt: 0, Jf: 0, K: 1024},
	{Code: 6, Jt: 0, Jf: 0, K: 0},
}
