package cfb

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"time"
	"unicode/utf16"
)

const (
	maxNameUnits  = 31
	maxStreamSize = math.MaxInt32 // version 3 files cap streams at 2 GiB
)

type Storage struct {
	name      string
	isRoot    bool
	clsid     CLSID
	stateBits uint32
	created   time.Time
	modified  time.Time
	entries   []builderChild
	taken     map[string]bool
}

type builderChild struct {
	name  string
	units []uint16 // the name in UTF-16
	key   []uint16 // units in upper case, which order and compare names
	sub   *Storage
	data  []byte
	size  int64
	open  func() (io.Reader, error) // the content of a stream added with AddStreamFrom
}

func NewRoot() *Storage {
	return &Storage{name: "Root Entry", isRoot: true, taken: map[string]bool{}}
}

func (s *Storage) SetCLSID(c CLSID) {
	s.clsid = c
}

func (s *Storage) SetStateBits(bits uint32) {
	s.stateBits = bits
}

func (s *Storage) SetTimes(created, modified time.Time) {
	s.created = created
	s.modified = modified
}

func (s *Storage) AddStorage(name string) (*Storage, error) {
	units, key, err := s.reserve(name)
	if err != nil {
		return nil, err
	}

	sub := &Storage{name: name, taken: map[string]bool{}}
	s.entries = append(s.entries, builderChild{name: name, units: units, key: key, sub: sub})
	return sub, nil
}

func (s *Storage) AddStream(name string, data []byte) error {
	if int64(len(data)) > maxStreamSize {
		return fmt.Errorf("cfb: stream %q exceeds 2 GiB", name)
	}

	units, key, err := s.reserve(name)
	if err != nil {
		return err
	}

	s.entries = append(s.entries, builderChild{name: name, units: units, key: key, data: data, size: int64(len(data))})
	return nil
}

func (s *Storage) AddStreamFrom(name string, size int64, open func() (io.Reader, error)) error {
	if size < 0 || size > maxStreamSize {
		return fmt.Errorf("cfb: stream %q size %d is not between 0 and 2 GiB", name, size)
	}

	if open == nil {
		return fmt.Errorf("cfb: stream %q has no content", name)
	}

	units, key, err := s.reserve(name)
	if err != nil {
		return err
	}

	s.entries = append(s.entries, builderChild{name: name, units: units, key: key, size: size, open: open})
	return nil
}

func (s *Storage) reserve(name string) (units, key []uint16, err error) {
	units = nameUnits(name)
	if len(units) == 0 || len(units) > maxNameUnits {
		return nil, nil, fmt.Errorf("cfb: name %q must be 1-%d UTF-16 code units", name, maxNameUnits)
	}

	for _, r := range name {
		if r == '/' || r == '\\' || r == ':' || r == '!' {
			return nil, nil, fmt.Errorf("cfb: name %q contains a reserved character", name)
		}
	}

	key = upperAll(units)
	taken := takenKey(key)
	if s.taken[taken] {
		return nil, nil, fmt.Errorf("cfb: duplicate name %q", name)
	}

	s.taken[taken] = true
	return units, key, nil
}

// nameUnits encodes a name in UTF-16, directly for an ASCII name.
func nameUnits(name string) []uint16 {
	for i := 0; i < len(name); i++ {
		if name[i] >= 0x80 {
			return utf16.Encode([]rune(name))
		}
	}

	units := make([]uint16, len(name))
	for i := 0; i < len(name); i++ {
		units[i] = uint16(name[i])
	}
	return units
}

// takenKey turns upper-case code units into a map key: the bytes of an
// ASCII name, or a NUL, which names cannot hold, then the units.
func takenKey(key []uint16) string {
	ascii := true
	for _, u := range key {
		ascii = ascii && u < 0x80
	}

	if ascii {
		b := make([]byte, len(key))
		for i, u := range key {
			b[i] = byte(u)
		}
		return string(b)
	}

	b := make([]byte, 1, 1+2*len(key))
	for _, u := range key {
		b = byteOrder.AppendUint16(b, u)
	}
	return string(b)
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
	units, key         []uint16
	open               func() (io.Reader, error)
	kind               EntryKind
	color              uint8
	left, right, child uint32
	clsid              CLSID
	stateBits          uint32
	created, modified  uint64
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
	miniFat, miniSize := layoutMiniStream(small)

	alloc := &sectorAllocator{}
	sectors := 0
	for _, e := range large {
		n := divRoundUp(int(e.size), sectorSize512)
		e.start = alloc.chain(n)
		sectors += n
	}
	root := entries[0]
	root.start = sectorEndOfChain
	if len(miniFat) > 0 {
		root.start = alloc.chain(divRoundUp(miniSize, sectorSize512))
		root.size = uint64(miniSize)
		sectors += divRoundUp(miniSize, sectorSize512)
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

	// The size of the file is known: a buffer as large as it is enough.
	sectors += miniFatSectors + dirSectors + fatSectors + difatSectors
	total := (1 + sectors) * sectorSize512
	if g, ok := w.(interface{ Grow(n int) }); ok {
		g.Grow(total)
	}
	out := &countWriter{w: bufio.NewWriterSize(w, min(64*1024, total))}
	out.write(head)
	for _, e := range large {
		out.writeStream(e, sectorSize512)
	}
	if len(miniFat) > 0 {
		for _, e := range small {
			out.writeStream(e, miniSectSize)
		}
		if r := miniSize % sectorSize512; r != 0 {
			out.write(zeroSector[:sectorSize512-r])
		}
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
		units: nameUnits("Root Entry"),
		kind:  KindRoot,
		color: nodeColorBlack,
		left:  noChild,
		right: noChild,
		child: noChild,
		clsid: s.clsid,
		// The root entry's creation time must be zero.
		stateBits: s.stateBits,
		modified:  timeToFiletime(s.modified),
	}}

	var walk func(parentIdx int, dir *Storage)
	walk = func(parentIdx int, dir *Storage) {
		ids := make([]int, len(dir.entries))
		for i, c := range dir.entries {
			e := &plannedEntry{name: c.name, units: c.units, key: c.key, left: noChild, right: noChild, child: noChild}
			if c.sub != nil {
				e.kind = KindStorage
				e.clsid = c.sub.clsid
				e.stateBits = c.sub.stateBits
				e.created = timeToFiletime(c.sub.created)
				e.modified = timeToFiletime(c.sub.modified)
			} else {
				e.kind = KindStream
				e.data, e.open = c.data, c.open
				e.size = uint64(c.size)
			}

			entries = append(entries, e)
			ids[i] = len(entries) - 1
		}

		// sortedIDs is ids reordered by name for the tree layout; origIDs
		// keeps the original per-child indices so the recursion below can
		// still find each child's entry after the sort below reorders ids.
		origIDs := append([]int(nil), ids...)
		sort.Slice(ids, func(i, j int) bool {
			return compareKeys(entries[ids[i]].key, entries[ids[j]].key) < 0
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

func layoutMiniStream(small []*plannedEntry) (miniFat []uint32, size int) {
	sectors := 0
	for _, e := range small {
		sectors += divRoundUp(int(e.size), miniSectSize)
	}

	miniFat = make([]uint32, 0, sectors)
	for _, e := range small {
		n := divRoundUp(int(e.size), miniSectSize)
		e.start = uint32(len(miniFat))
		for k := range n {
			next := uint32(len(miniFat) + 1) // len(miniFat) already grew by k from the appends below
			if k == n-1 {
				next = sectorEndOfChain
			}
			miniFat = append(miniFat, next)
		}
	}
	return miniFat, sectors * miniSectSize
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
		units := e.units
		if units == nil {
			units = nameUnits(e.name)
		}
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
		byteOrder.PutUint32(b[0x60:], e.stateBits)
		byteOrder.PutUint64(b[0x64:], e.created)
		byteOrder.PutUint64(b[0x6C:], e.modified)
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

func (c *countWriter) writeStream(e *plannedEntry, align int) {
	if e.open == nil {
		c.writeAligned(e.data, align)
		return
	}
	if c.err != nil {
		return
	}

	r, err := e.open()
	if err != nil {
		c.err = fmt.Errorf("cfb: stream %q: %w", e.name, err)
		return
	}
	if closer, ok := r.(io.Closer); ok {
		defer func() { _ = closer.Close() }()
	}

	n, err := io.CopyN(c.w, r, int64(e.size))
	c.n += n
	if err == io.EOF {
		err = fmt.Errorf("cfb: stream %q has %d of its %d bytes", e.name, n, e.size)
	}
	if err != nil {
		c.err = err
		return
	}
	if r := int(e.size % uint64(align)); r != 0 {
		c.write(zeroSector[:align-r])
	}
}

func (c *countWriter) writeAligned(p []byte, align int) {
	c.write(p)
	if r := len(p) % align; r != 0 {
		c.write(zeroSector[:align-r])
	}
}
