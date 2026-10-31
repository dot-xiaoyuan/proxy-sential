package devicesignal

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// clientHelloJA4 follows the FoxIO JA4 TLS-over-TCP format. It only fingerprints
// a complete ClientHello; a clipped packet must not become an apparent stack.
func clientHelloJA4(record []byte) string {
	if clientHelloJA3(record) == "" {
		return ""
	}
	return clientHelloJA4Validated(record)
}

// The caller already verified the complete record with clientHelloJA3.
func clientHelloJA4Validated(record []byte) string {
	body := record[9:]
	version := binary.BigEndian.Uint16(body[:2])
	hasSupportedVersions := false
	pos := 34
	pos += 1 + int(body[pos]) // session ID
	cipherLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	ciphers := make([]uint16, 0, cipherLen/2)
	for i := 0; i < cipherLen; i += 2 {
		value := binary.BigEndian.Uint16(body[pos+i : pos+i+2])
		if !ja4GREASE(value) {
			ciphers = append(ciphers, value)
		}
	}
	pos += cipherLen
	pos += 1 + int(body[pos]) // compression methods
	extensions := []uint16{}
	signatures := []uint16{}
	alpn := "00"
	sni := false
	if pos < len(body) {
		pos += 2 // JA3 has already checked the exact extension block length.
		for pos < len(body) {
			kind := binary.BigEndian.Uint16(body[pos : pos+2])
			length := int(binary.BigEndian.Uint16(body[pos+2 : pos+4]))
			data := body[pos+4 : pos+4+length]
			pos += 4 + length
			if ja4GREASE(kind) {
				continue
			}
			extensions = append(extensions, kind)
			switch kind {
			case 0:
				sni = true
			case 16:
				if len(data) < 3 || int(binary.BigEndian.Uint16(data[:2])) != len(data)-2 || int(data[2]) > len(data)-3 {
					return ""
				}
				if data[2] > 0 {
					value := data[3 : 3+int(data[2])]
					alpn = ja4ALPN(value)
				}
			case 43:
				if len(data) < 1 || int(data[0]) != len(data)-1 || (len(data)-1)%2 != 0 {
					return ""
				}
				if !hasSupportedVersions {
					version = 0
					hasSupportedVersions = true
				}
				for i := 1; i < len(data); i += 2 {
					candidate := binary.BigEndian.Uint16(data[i : i+2])
					if !ja4GREASE(candidate) && candidate > version {
						version = candidate
					}
				}
			case 13:
				if len(data) < 2 || int(binary.BigEndian.Uint16(data[:2])) != len(data)-2 || (len(data)-2)%2 != 0 {
					return ""
				}
				for i := 2; i < len(data); i += 2 {
					candidate := binary.BigEndian.Uint16(data[i : i+2])
					if !ja4GREASE(candidate) {
						signatures = append(signatures, candidate)
					}
				}
			}
		}
	}
	versionCode := map[uint16]string{0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3", 0x0002: "s2"}[version]
	if versionCode == "" {
		versionCode = "00"
	}
	sniCode := "i"
	if sni {
		sniCode = "d"
	}
	return fmt.Sprintf("t%s%s%02d%02d%s_%s_%s", versionCode, sniCode, min(len(ciphers), 99), min(len(extensions), 99), alpn, ja4CipherHash(ciphers), ja4ExtensionHash(extensions, signatures))
}

func ja4GREASE(value uint16) bool {
	return value&0x0f0f == 0x0a0a && byte(value>>8) == byte(value)
}

func ja4ALPN(value []byte) string {
	if len(value) == 0 {
		return "00"
	}
	first, last := value[0], value[len(value)-1]
	alphaNum := func(c byte) bool { return c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' }
	if alphaNum(first) && alphaNum(last) {
		return string([]byte{first, last})
	}
	return fmt.Sprintf("%02x", first)[0:1] + fmt.Sprintf("%02x", last)[1:2]
}

func ja4CipherHash(ciphers []uint16) string {
	if len(ciphers) == 0 {
		return "000000000000"
	}
	items := append([]uint16(nil), ciphers...)
	sort.Slice(items, func(i, j int) bool { return items[i] < items[j] })
	return ja4Hash(ja4HexList(items))
}

func ja4ExtensionHash(extensions, signatures []uint16) string {
	items := make([]uint16, 0, len(extensions))
	for _, value := range extensions {
		if value != 0 && value != 16 && !ja4GREASE(value) {
			items = append(items, value)
		}
	}
	if len(items) == 0 {
		return "000000000000"
	}
	sort.Slice(items, func(i, j int) bool { return items[i] < items[j] })
	input := ja4HexList(items)
	if len(signatures) > 0 {
		input += "_" + ja4HexList(signatures)
	}
	return ja4Hash(input)
}

func ja4HexList(values []uint16) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, fmt.Sprintf("%04x", value))
	}
	return strings.Join(parts, ",")
}

func ja4Hash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:12]
}
