package ja4_test

import (
	"testing"

	"github.com/AmanamIsrael/lookout/sensor"
)

// Worked example from FoxIO's JA4 technical details.
var (
	specCiphers = []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035}
	specExts    = []uint16{0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023, 0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015}
	specSigs    = []uint16{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601}
	tls13       = []uint16{0x0304, 0x0303}
)

func TestSpecExample(t *testing.T) {
	got := sensor.JA4FromParts(specCiphers, specExts, specSigs, tls13, []string{"h2", "http/1.1"})
	if want := "t13d1516h2_8daaf6152771_e5627efa2ab1"; got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestGREASEIsIgnored(t *testing.T) {
	grease := func(in []uint16) []uint16 { return append([]uint16{0x0a0a}, append(in, 0xfafa)...) }
	got := sensor.JA4FromParts(grease(specCiphers), grease(specExts), grease(specSigs), grease(tls13), []string{"h2"})
	if want := "t13d1516h2_8daaf6152771_e5627efa2ab1"; got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestALPNAndSNIVariants(t *testing.T) {
	noSNI := []uint16{0x000a, 0x000d}
	cases := []struct {
		name string
		exts []uint16
		alpn []string
		want string // first part only
	}{
		{"no alpn", specExts, nil, "t13d151600"},
		{"http/1.1", specExts, []string{"http/1.1"}, "t13d1516h1"},
		{"no sni", noSNI, []string{"h2"}, "t13i1502h2"},
		{"non-alphanumeric alpn uses hex", specExts, []string{"\x20a"}, "t13d151621"},
	}
	for _, c := range cases {
		got := sensor.JA4FromParts(specCiphers, c.exts, specSigs, tls13, c.alpn)
		if got[:10] != c.want {
			t.Errorf("%s: got %s, want prefix %s", c.name, got, c.want)
		}
	}
}

func TestEmptyLists(t *testing.T) {
	got := sensor.JA4FromParts(nil, nil, nil, []uint16{0x0303}, nil)
	if want := "t12i000000_000000000000_000000000000"; got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}
