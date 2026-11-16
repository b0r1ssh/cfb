// Package cfb reads and writes the Compound File Binary File Format
// ([MS-CFB]), the structured-storage container behind legacy Microsoft
// formats such as .msg, .doc, .xls, .ppt and .msi.
//
// A compound file is a small file system: a tree of storages (directories)
// and streams (files). The package only deals with that container; it has
// no knowledge of what any particular format stores in its streams.
//
// Use [Open] to read a file and walk the tree from
// [Reader.Root]. Use [NewRoot] to build a tree in memory and
// [Storage.WriteTo] to serialize it.
//
// [MS-CFB]: https://learn.microsoft.com/openspecs/windows_protocols/ms-cfb
package cfb

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
)

var (
	// ErrNotCompoundFile reports that the input lacks the compound file
	// signature or is too short to hold a header.
	ErrNotCompoundFile = errors.New("cfb: not a compound file")
	// ErrUnsupported reports a compound file whose version or sector
	// geometry this package cannot read.
	ErrUnsupported = errors.New("cfb: unsupported compound file")
	// ErrCorrupt reports a structurally invalid compound file.
	ErrCorrupt = errors.New("cfb: corrupt compound file")
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

	// Timestamps are stored as FILETIME: 100 ns ticks since 1601-01-01 UTC.
	filetimeTicksPerSecond = 10_000_000
	filetimeUnixEpochSecs  = 11_644_473_600 // seconds from 1601-01-01 to 1970-01-01
)

var (
	byteOrder = binary.LittleEndian
	magic     = [8]byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1} // magic number identifying CFB files
)

type EntryKind uint8

const (
	KindUnknown EntryKind = 0 // unallocated or unrecognized entry
	KindStorage EntryKind = 1 // storage: contains other entries
	KindStream  EntryKind = 2 // stream: contains bytes
	KindRoot    EntryKind = 5 // root storage
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

func filetimeToTime(ft uint64) time.Time {
	if ft == 0 {
		return time.Time{}
	}
	secs := int64(ft/filetimeTicksPerSecond) - filetimeUnixEpochSecs
	nanos := int64(ft%filetimeTicksPerSecond) * 100
	return time.Unix(secs, nanos).UTC()
}

func timeToFiletime(t time.Time) uint64 {
	if t.IsZero() {
		return 0
	}
	secs := t.Unix() + filetimeUnixEpochSecs
	if secs < 0 {
		return 0
	}
	return uint64(secs)*filetimeTicksPerSecond + uint64(t.Nanosecond()/100)
}

func sortKey(name string) []uint16 {
	return upperAll(nameUnits(name))
}

func upperCodeUnit(u uint16) uint16 {
	if u < 0x80 {
		if u >= 'a' && u <= 'z' {
			return u - 'a' + 'A'
		}
		return u
	}
	if u >= 0xD800 && u <= 0xDFFF {
		return u
	}
	if up := unicode.ToUpper(rune(u)); up <= 0xFFFF {
		return uint16(up)
	}
	return u
}

func compareNames(a, b string) int {
	return compareKeys(sortKey(a), sortKey(b))
}

// compareKeys orders names by their upper-case code units: shorter names
// first, then unit by unit ([MS-CFB] 2.6.4).
func compareKeys(ka, kb []uint16) int {
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
