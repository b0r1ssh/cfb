package cfb

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf16"
)

const (
	sectorSize512  = 512  // size of a regular sector in bytes
	miniSectSize   = 64   // size of a mini sector in bytes
	miniStreamCap  = 4096 // streams this size or larger live in regular sectors
	direntSize     = 128  // size of a directory entry in bytes
	headerFatSlots = 109  // FAT sector locators stored directly in the header

	sectorMaxRegular = 0xFFFFFFFA // maximum regular sector number
	sectorDIFAT      = 0xFFFFFFFC // DIFAT sector marker
	sectorFAT        = 0xFFFFFFFD // FAT sector marker
	sectorEndOfChain = 0xFFFFFFFE // end-of-chain marker
	sectorFree       = 0xFFFFFFFF // free sector marker
	noChild          = 0xFFFFFFFF // no child marker

	nodeColorRed   = 0
	nodeColorBlack = 1
)

var (
	byteOrder = binary.LittleEndian
	magic     = [8]byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1} // magic number identifying CFB files
)

type EntryKind uint8

const (
	KindUnknown EntryKind = 0
	KindStorage EntryKind = 1
	KindStream  EntryKind = 2
	KindRoot    EntryKind = 5
)

func (k EntryKind) String() string {
	switch k {
	case KindStorage:
		return "storage"
	case KindStream:
		return "stream"
	case KindRoot:
		return "root"
	default:
		return "unknown"
	}
}

type CLSID [16]byte

func ParseCLSID(s string) (CLSID, error) {
	var c CLSID
	s = strings.Trim(s, "{}")
	groups := strings.Split(s, "-")
	if len(groups) != 5 ||
		len(groups[0]) != 8 || len(groups[1]) != 4 || len(groups[2]) != 4 ||
		len(groups[3]) != 4 || len(groups[4]) != 12 {
		return c, fmt.Errorf("cfb: %q is not a valid CLSID", s)
	}

	raw, err := hex.DecodeString(strings.Join(groups, ""))
	if err != nil {
		return c, fmt.Errorf("cfb: %q is not a valid CLSID: %w", s, err)
	}

	c[0], c[1], c[2], c[3] = raw[3], raw[2], raw[1], raw[0] // Data1, little-endian
	c[4], c[5] = raw[5], raw[4]                             // Data2
	c[6], c[7] = raw[7], raw[6]                             // Data3
	copy(c[8:], raw[8:])                                    // Data4, byte order unchanged
	return c, nil
}

func MustParseCLSID(s string) CLSID {
	c, err := ParseCLSID(s)
	if err != nil {
		panic(err)
	}
	return c
}

func (c CLSID) String() string {
	return fmt.Sprintf("%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		c[3], c[2], c[1], c[0], c[5], c[4], c[7], c[6],
		c[8], c[9], c[10], c[11], c[12], c[13], c[14], c[15])
}

func (c CLSID) IsZero() bool { return c == CLSID{} }

func sortKey(name string) []uint16 {
	units := utf16.Encode([]rune(name))
	out := make([]uint16, len(units))
	for i, u := range units {
		out[i] = upperCodeUnit(u)
	}
	return out
}

func upperCodeUnit(u uint16) uint16 {
	if u >= 0xD800 && u <= 0xDFFF {
		return u
	}
	if up := unicode.ToUpper(rune(u)); up <= 0xFFFF {
		return uint16(up)
	}
	return u
}

func compareNames(a, b string) int {
	ka, kb := sortKey(a), sortKey(b)
	if len(ka) != len(kb) {
		if len(ka) < len(kb) {
			return -1
		}
		return 1
	}
	for i := range ka {
		if ka[i] != kb[i] {
			if ka[i] < kb[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

func divRoundUp(n, unit int) int {
	return (n + unit - 1) / unit
}
