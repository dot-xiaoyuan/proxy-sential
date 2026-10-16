package devicesignal

import (
	"crypto/md5" // JA3's interoperable identifier, not a security primitive.
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"strings"
)

// Deliberately does not reassemble TCP. Only a complete, internally consistent
// ClientHello in this record may contribute a fingerprint.
func clientHelloJA3(record []byte) string {
	if len(record) < 9 || record[0] != 22 || record[1] != 3 || record[5] != 1 {
		return ""
	}
	n := int(binary.BigEndian.Uint16(record[3:5]))
	if n < 4 || len(record) < 5+n {
		return ""
	}
	size := int(record[6])<<16 | int(record[7])<<8 | int(record[8])
	if size+4 != n || size < 38 {
		return ""
	}
	b := record[9 : 5+n]
	pos := 34
	take := func(n int) []byte {
		if n < 0 || pos+n > len(b) {
			return nil
		}
		v := b[pos : pos+n]
		pos += n
		return v
	}
	sid := take(1)
	if sid == nil || take(int(sid[0])) == nil {
		return ""
	}
	l := take(2)
	if l == nil {
		return ""
	}
	cl := int(binary.BigEndian.Uint16(l))
	if cl == 0 || cl%2 != 0 {
		return ""
	}
	cs := take(cl)
	if cs == nil {
		return ""
	}
	l = take(1)
	if l == nil || l[0] == 0 || take(int(l[0])) == nil {
		return ""
	}
	grease := func(v uint16) bool { return v&0x0f0f == 0x0a0a && byte(v>>8) == byte(v) }
	words := func(v []byte) string {
		out := []string{}
		for i := 0; i < len(v); i += 2 {
			n := binary.BigEndian.Uint16(v[i : i+2])
			if !grease(n) {
				out = append(out, strconv.Itoa(int(n)))
			}
		}
		return strings.Join(out, "-")
	}
	extensions, curves, points := []string{}, "", ""
	if pos < len(b) {
		l = take(2)
		if l == nil || pos+int(binary.BigEndian.Uint16(l)) != len(b) {
			return ""
		}
		seen := map[uint16]bool{}
		for pos < len(b) {
			h := take(4)
			if h == nil {
				return ""
			}
			kind := binary.BigEndian.Uint16(h)
			v := take(int(binary.BigEndian.Uint16(h[2:])))
			if v == nil || seen[kind] {
				return ""
			}
			seen[kind] = true
			if !grease(kind) {
				extensions = append(extensions, strconv.Itoa(int(kind)))
			}
			switch kind {
			case 10:
				if len(v) < 2 || int(binary.BigEndian.Uint16(v)) != len(v)-2 || (len(v)-2)%2 != 0 {
					return ""
				}
				curves = words(v[2:])
			case 11:
				if len(v) < 1 || int(v[0]) != len(v)-1 {
					return ""
				}
				p := []string{}
				for _, n := range v[1:] {
					p = append(p, strconv.Itoa(int(n)))
				}
				points = strings.Join(p, "-")
			}
		}
	}
	raw := strings.Join([]string{strconv.Itoa(int(binary.BigEndian.Uint16(b))), words(cs), strings.Join(extensions, "-"), curves, points}, ",")
	sum := md5.Sum([]byte(raw))
	return hex.EncodeToString(sum[:])
}
