package sensor

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
)

// JA4 fingerprints a TLS ClientHello per the FoxIO JA4 spec
// (github.com/FoxIO-LLC/ja4, technical_details/JA4.md). TCP only, so the
// protocol prefix is always "t".
func JA4(hello *tls.ClientHelloInfo) string {
	sigs := make([]uint16, len(hello.SignatureSchemes))
	for i, s := range hello.SignatureSchemes {
		sigs[i] = uint16(s)
	}
	return JA4FromParts(hello.CipherSuites, hello.Extensions, sigs, hello.SupportedVersions, hello.SupportedProtos)
}

// JA4FromParts computes JA4 from raw ClientHello values.
func JA4FromParts(ciphers, extensions, sigAlgs, versions []uint16, alpn []string) string {
	ciphers = withoutGREASE(ciphers)
	extensions = withoutGREASE(extensions)
	sigAlgs = withoutGREASE(sigAlgs)

	sni := "i"
	if slices.Contains(extensions, 0x0000) {
		sni = "d"
	}

	a := fmt.Sprintf("t%s%s%02d%02d%s",
		tlsVersion(withoutGREASE(versions)), sni,
		min(len(ciphers), 99), min(len(extensions), 99), alpnChars(alpn))

	slices.Sort(ciphers)
	b := hash12(hexList(ciphers))

	var exts []uint16
	for _, e := range extensions {
		if e != 0x0000 && e != 0x0010 { // SNI and ALPN are already in part a
			exts = append(exts, e)
		}
	}
	slices.Sort(exts)
	c := "000000000000"
	if len(exts) > 0 {
		in := hexList(exts)
		if len(sigAlgs) > 0 {
			in += "_" + hexList(sigAlgs) // original order, not sorted
		}
		c = hash12(in)
	}
	return a + "_" + b + "_" + c
}

func isGREASE(v uint16) bool { return v&0x0f0f == 0x0a0a && v>>8 == v&0xff }

func withoutGREASE(in []uint16) []uint16 {
	out := make([]uint16, 0, len(in))
	for _, v := range in {
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

func tlsVersion(versions []uint16) string {
	if len(versions) == 0 {
		return "00"
	}
	switch slices.Max(versions) {
	case tls.VersionTLS13:
		return "13"
	case tls.VersionTLS12:
		return "12"
	case tls.VersionTLS11:
		return "11"
	case tls.VersionTLS10:
		return "10"
	case 0x0300:
		return "s3"
	default:
		return "00"
	}
}

func alpnChars(alpn []string) string {
	if len(alpn) == 0 || alpn[0] == "" {
		return "00"
	}
	v := alpn[0]
	first, last := v[0], v[len(v)-1]
	if isAlnum(first) && isAlnum(last) {
		return string([]byte{first, last})
	}
	h := hex.EncodeToString([]byte(v))
	return string([]byte{h[0], h[len(h)-1]})
}

func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
}

func hexList(vs []uint16) string {
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(parts, ",")
}

func hash12(s string) string {
	if s == "" {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}
