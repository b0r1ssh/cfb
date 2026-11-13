package cfb

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"unicode/utf16"
)

const maxNameUnits = 31

type Storage struct {
	name    string
	isRoot  bool
	clsid   CLSID
	entries []builderChild
	taken   map[string]bool
}

type builderChild struct {
	name string
	sub  *Storage
	data []byte
}

func NewRoot() *Storage {
	return &Storage{name: "Root Entry", isRoot: true, taken: map[string]bool{}}
}

func (s *Storage) SetCLSID(c CLSID) {
	s.clsid = c
}

func (s *Storage) AddStorage(name string) (*Storage, error) {
	if err := s.reserve(name); err != nil {
		return nil, err
	}

	sub := &Storage{name: name, taken: map[string]bool{}}
	s.entries = append(s.entries, builderChild{name: name, sub: sub})
	return sub, nil
}

func (s *Storage) AddStream(name string, data []byte) error {
	if int64(len(data)) > math.MaxUint32 {
		return fmt.Errorf("cfb: stream %q exceeds 4 GiB", name)
	}

	if err := s.reserve(name); err != nil {
		return err
	}

	s.entries = append(s.entries, builderChild{name: name, data: data})
	return nil
}

func (s *Storage) reserve(name string) error {
	units := utf16.Encode([]rune(name))
	if len(units) == 0 || len(units) > maxNameUnits {
		return fmt.Errorf("cfb: name %q must be 1-%d UTF-16 code units", name, maxNameUnits)
	}

	for _, r := range name {
		if r == '/' || r == '\\' || r == ':' || r == '!' {
			return fmt.Errorf("cfb: name %q contains a reserved character", name)
		}
	}

	key := string(utf16.Decode(upperAll(units)))
	if s.taken[key] {
		return fmt.Errorf("cfb: duplicate name %q", name)
	}

	s.taken[key] = true
	return nil
}

func upperAll(units []uint16) []uint16 {
	out := make([]uint16, len(units))
	for i, u := range units {
		out[i] = upperCodeUnit(u)
	}
	return out
}

type plannedEntry struct {
	name               string
	kind               EntryKind
	color              uint8
	left, right, child uint32
	clsid              CLSID
	start              uint32
	size               uint64
	data               []byte
	depth              int
}

func (s *Storage) WriteTo(w io.Writer) (int64, error) {
	if !s.isRoot {
		return 0, errors.New("cfb: WriteTo must be called on the storage returned by NewRoot")
	}

	entries := s.buildPlan()

	small, large := splitBySize(entries[1:])
	miniFat, miniBytes := layoutMiniStream(small)

	alloc := &sectorAllocator{}
	for _, e := range large {
		e.start = alloc.chain(divRoundUp(len(e.data), sectorSize512))
	}
	root := entries[0]
	root.start = sectorEndOfChain
	if len(miniFat) > 0 {
		root.start = alloc.chain(divRoundUp(len(miniBytes), sectorSize512))
		root.size = uint64(len(miniBytes))
	}
	miniFatSectors := divRoundUp(len(miniFat)*4, sectorSize512)
	miniFatStart := uint32(sectorEndOfChain)
	if miniFatSectors > 0 {
		miniFatStart = alloc.chain(miniFatSectors)
	}
	dirSectors := divRoundUp(len(entries)*direntSize, sectorSize512)
	dirStart := alloc.chain(dirSectors)

	fatStart, fatSectors, difatStart, difatSectors := alloc.layoutFatAndDifat()

	head := buildHeader(headerFields{
		fatSectors: fatSectors, dirStart: dirStart, miniFatStart: miniFatStart,
		miniFatSectors: miniFatSectors, difatStart: difatStart, difatSectors: difatSectors,
		fatStart: fatStart,
	})

	out := &countWriter{w: bufio.NewWriterSize(w, 64*1024)}
	out.write(head)
	for _, e := range large {
		out.writeAligned(e.data, sectorSize512)
	}
	if len(miniFat) > 0 {
		out.writeAligned(miniBytes, sectorSize512)
	}
	if miniFatSectors > 0 {
		out.write(encodeU32Table(miniFat, miniFatSectors*sectorSize512/4))
	}
	out.write(encodeDirentArray(entries, dirSectors*sectorSize512/direntSize))
	out.write(encodeU32Table(alloc.fat, fatSectors*sectorSize512/4))
	out.write(encodeDifat(fatStart, fatSectors, difatStart, difatSectors))

	if out.err == nil {
		out.err = out.w.(*bufio.Writer).Flush()
	}

	return out.n, out.err
}

func (s *Storage) buildPlan() []*plannedEntry {
	entries := []*plannedEntry{{
		name:  "Root Entry",
		kind:  KindRoot,
		color: nodeColorBlack,
		left:  noChild,
		right: noChild,
		child: noChild,
		clsid: s.clsid,
	}}

	var walk func(parentIdx int, dir *Storage)
	walk = func(parentIdx int, dir *Storage) {
		ids := make([]int, len(dir.entries))
		for i, c := range dir.entries {
			e := &plannedEntry{name: c.name, left: noChild, right: noChild, child: noChild}
			if c.sub != nil {
				e.kind = KindStorage
				e.clsid = c.sub.clsid
			} else {
				e.kind = KindStream
				e.data = c.data
				e.size = uint64(len(c.data))
			}

			entries = append(entries, e)
			ids[i] = len(entries) - 1
		}

		// sortedIDs is ids reordered by name for the tree layout; origIDs
		// keeps the original per-child indices so the recursion below can
		// still find each child's entry after the sort below reorders ids.
		origIDs := append([]int(nil), ids...)
		sort.Slice(ids, func(i, j int) bool {
			return compareNames(entries[ids[i]].name, entries[ids[j]].name) < 0
		})
		entries[parentIdx].child = buildBalancedBST(entries, ids, 0)
		colorByDepth(entries, ids)
		for i, c := range dir.entries {
			if c.sub != nil {
				walk(origIDs[i], c.sub)
			}
		}
	}

	walk(0, s)
	return entries
}

func buildBalancedBST(entries []*plannedEntry, ids []int, depth int) uint32 {
	if len(ids) == 0 {
		return noChild
	}

	mid := len(ids) / 2
	entries[ids[mid]].depth = depth
	entries[ids[mid]].left = buildBalancedBST(entries, ids[:mid], depth+1)
	entries[ids[mid]].right = buildBalancedBST(entries, ids[mid+1:], depth+1)
	return uint32(ids[mid])
}

func colorByDepth(entries []*plannedEntry, ids []int) {
	maxDepth := 0
	for _, id := range ids {
		if entries[id].depth > maxDepth {
			maxDepth = entries[id].depth
		}
	}

	for _, id := range ids {
		if maxDepth > 0 && entries[id].depth == maxDepth {
			entries[id].color = nodeColorRed
		} else {
			entries[id].color = nodeColorBlack
		}
	}
}

func splitBySize(entries []*plannedEntry) (small, large []*plannedEntry) {
	for _, e := range entries {
		if e.kind != KindStream {
			continue
		}
		switch {
		case e.size == 0:
			e.start = sectorEndOfChain
		case e.size < miniStreamCap:
			small = append(small, e)
		default:
			large = append(large, e)
		}
	}
	return small, large
}

func layoutMiniStream(small []*plannedEntry) (miniFat []uint32, data []byte) {
	for _, e := range small {
		n := divRoundUp(len(e.data), miniSectSize)
		e.start = uint32(len(miniFat))
		for k := range n {
			next := uint32(len(miniFat) + 1) // len(miniFat) already grew by k from the appends below
			if k == n-1 {
				next = sectorEndOfChain
			}
			miniFat = append(miniFat, next)
		}
		data = append(data, e.data...)
		if pad := len(e.data) % miniSectSize; pad != 0 {
			data = append(data, make([]byte, miniSectSize-pad)...)
		}
	}
	return miniFat, data
}

type sectorAllocator struct {
	fat []uint32
}

func (a *sectorAllocator) chain(n int) uint32 {
	start := uint32(len(a.fat))
	for k := 0; k < n; k++ {
		next := uint32(len(a.fat) + 1)
		if k == n-1 {
			next = sectorEndOfChain
		}
		a.fat = append(a.fat, next)
	}
	return start
}

func (a *sectorAllocator) layoutFatAndDifat() (fatStart uint32, fatSectors int, difatStart uint32, difatSectors int) {
	const u32PerSector = sectorSize512 / 4
	const difatSlotsPerSector = u32PerSector - 1 // last slot chains to the next DIFAT sector

	before := len(a.fat)
	for {
		difat := 0
		if fatSectors > headerFatSlots {
			difat = divRoundUp(fatSectors-headerFatSlots, difatSlotsPerSector)
		}
		need := divRoundUp(before+fatSectors+difat, u32PerSector)
		if need <= fatSectors {
			difatSectors = difat
			break
		}
		fatSectors = need
	}
	fatStart = a.chain(fatSectors)
	for k := 0; k < fatSectors; k++ {
		a.fat[int(fatStart)+k] = sectorFAT
	}
	if difatSectors > 0 {
		difatStart = a.chain(difatSectors)
		for k := 0; k < difatSectors; k++ {
			a.fat[int(difatStart)+k] = sectorDIFAT
		}
	}
	for len(a.fat) < fatSectors*u32PerSector {
		a.fat = append(a.fat, sectorFree)
	}
	return fatStart, fatSectors, difatStart, difatSectors
}

type headerFields struct {
	fatSectors, miniFatSectors, difatSectors int
	dirStart, miniFatStart, difatStart       uint32
	fatStart                                 uint32
}

func buildHeader(h headerFields) []byte {
	b := make([]byte, sectorSize512)
	copy(b, magic[:])
	byteOrder.PutUint16(b[0x18:], 0x003E) // minor version
	byteOrder.PutUint16(b[0x1A:], 0x0003) // major version: 3
	byteOrder.PutUint16(b[0x1C:], 0xFFFE) // byte order mark
	byteOrder.PutUint16(b[0x1E:], 9)      // sector shift: 2^9 = 512
	byteOrder.PutUint16(b[0x20:], 6)      // mini sector shift: 2^6 = 64
	byteOrder.PutUint32(b[0x2C:], uint32(h.fatSectors))
	byteOrder.PutUint32(b[0x30:], h.dirStart)
	byteOrder.PutUint32(b[0x38:], miniStreamCap)
	byteOrder.PutUint32(b[0x3C:], h.miniFatStart)
	byteOrder.PutUint32(b[0x40:], uint32(h.miniFatSectors))
	if h.difatSectors > 0 {
		byteOrder.PutUint32(b[0x44:], h.difatStart)
	} else {
		byteOrder.PutUint32(b[0x44:], sectorEndOfChain)
	}
	byteOrder.PutUint32(b[0x48:], uint32(h.difatSectors))
	for i := 0; i < headerFatSlots; i++ {
		v := uint32(sectorFree)
		if i < h.fatSectors {
			v = uint32(int(h.fatStart) + i)
		}
		byteOrder.PutUint32(b[0x4C+4*i:], v)
	}
	return b
}

func encodeDirentArray(entries []*plannedEntry, slots int) []byte {
	out := make([]byte, slots*direntSize)
	for i := range slots {
		b := out[i*direntSize : (i+1)*direntSize]
		if i >= len(entries) {
			byteOrder.PutUint32(b[0x44:], noChild)
			byteOrder.PutUint32(b[0x48:], noChild)
			byteOrder.PutUint32(b[0x4C:], noChild)
			continue
		}
		e := entries[i]
		units := utf16.Encode([]rune(e.name))
		for j, u := range units {
			byteOrder.PutUint16(b[2*j:], u)
		}
		byteOrder.PutUint16(b[0x40:], uint16((len(units)+1)*2))
		b[0x42] = byte(e.kind)
		b[0x43] = e.color
		byteOrder.PutUint32(b[0x44:], e.left)
		byteOrder.PutUint32(b[0x48:], e.right)
		byteOrder.PutUint32(b[0x4C:], e.child)
		copy(b[0x50:0x60], e.clsid[:])
		byteOrder.PutUint32(b[0x74:], e.start)
		byteOrder.PutUint64(b[0x78:], e.size)
	}
	return out
}

func encodeU32Table(vals []uint32, slots int) []byte {
	out := make([]byte, slots*4)
	for i := range slots {
		v := uint32(sectorFree)
		if i < len(vals) {
			v = vals[i]
		}
		byteOrder.PutUint32(out[4*i:], v)
	}
	return out
}

func encodeDifat(fatStart uint32, fatSectors int, difatStart uint32, difatSectors int) []byte {
	const perSector = sectorSize512/4 - 1
	out := make([]byte, difatSectors*sectorSize512)
	for d := range difatSectors {
		sec := out[d*sectorSize512 : (d+1)*sectorSize512]
		for j := range perSector {
			v := uint32(sectorFree)
			if k := headerFatSlots + d*perSector + j; k < fatSectors {
				v = uint32(int(fatStart) + k)
			}
			byteOrder.PutUint32(sec[4*j:], v)
		}
		next := uint32(sectorEndOfChain)
		if d < difatSectors-1 {
			next = difatStart + uint32(d) + 1
		}
		byteOrder.PutUint32(sec[4*perSector:], next)
	}
	return out
}

type countWriter struct {
	w   io.Writer
	n   int64
	err error
}

func (c *countWriter) write(p []byte) {
	if c.err != nil || len(p) == 0 {
		return
	}
	n, err := c.w.Write(p)
	c.n += int64(n)
	c.err = err
}

var zeroSector [sectorSize512]byte

func (c *countWriter) writeAligned(p []byte, align int) {
	c.write(p)
	if r := len(p) % align; r != 0 {
		c.write(zeroSector[:align-r])
	}
}
