package cfb

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
)

type Reader struct {
	src        io.ReaderAt
	size       int64
	version    uint16
	sectorSize int
	miniCutoff uint64

	fat     []uint32
	miniFat []uint32

	rootChain []uint32

	// The mini stream, read whole the first time a small stream is read.
	miniOnce sync.Once
	miniData []byte
	miniErr  error

	Root *Entry
}

func (r *Reader) Version() int {
	return int(r.version)
}

func (r *Reader) SectorSize() int {
	return r.sectorSize
}

type Entry struct {
	Name  string
	Kind  EntryKind
	CLSID CLSID
	// StateBits holds the application-defined flags of a storage.
	StateBits uint32
	// Created and Modified are the zero Time when the file does not record
	// them, which is always the case for streams.
	Created  time.Time
	Modified time.Time
	// Size is the length in bytes of a stream; it is 0 for storages.
	Size uint64
	// Children holds the entries of a storage, in the format's sort order
	// (shorter names first, then case-insensitively by code unit).
	Children []*Entry

	owner    *Reader
	startSec uint32
}

func (e *Entry) IsStorage() bool {
	return e.Kind == KindStorage
}

func (e *Entry) IsRoot() bool {
	return e.Kind == KindRoot
}

func (e *Entry) Find(name string) *Entry {
	for _, c := range e.Children {
		if strings.EqualFold(c.Name, name) {
			return c
		}
	}
	return nil
}

func (e *Entry) Lookup(path string) *Entry {
	cur := e
	for _, name := range strings.Split(path, "/") {
		if name == "" {
			continue
		}
		if cur = cur.Find(name); cur == nil {
			return nil
		}
	}
	return cur
}

func (e *Entry) Walk(fn func(path string, entry *Entry) error) error {
	return e.walk("", fn)
}

func (e *Entry) walk(prefix string, fn func(path string, entry *Entry) error) error {
	for _, c := range e.Children {
		p := prefix + c.Name
		if err := fn(p, c); err != nil {
			if errors.Is(err, fs.SkipDir) {
				continue
			}
			return err
		}
		if err := c.walk(p+"/", fn); err != nil {
			return err
		}
	}
	return nil
}

func (e *Entry) Open() (*Stream, error) {
	if e.Kind != KindStream {
		return nil, fmt.Errorf("cfb: %q is a %s, not a stream", e.Name, e.Kind)
	}

	if e.Size > math.MaxInt64 {
		return nil, fmt.Errorf("%w: stream %q has an impossible size", ErrCorrupt, e.Name)
	}

	mini := e.Size < e.owner.miniCutoff
	unit := uint64(e.owner.sectorSize)
	if mini {
		unit = miniSectSize
	}

	// Computed in uint64 so a huge size taken from the file cannot overflow.
	limit := math.MaxInt
	if sectors := (e.Size + unit - 1) / unit; sectors < math.MaxInt {
		limit = int(sectors)
	}

	chain, err := e.owner.sectorChain(e.startSec, mini, limit)
	if err != nil {
		return nil, err
	}

	return &Stream{r: e.owner, mini: mini, chain: chain, size: int64(e.Size)}, nil
}

func (e *Entry) Bytes() ([]byte, error) {
	s, err := e.Open()
	if err != nil {
		return nil, err
	}

	// The buffer holds the stream, or what its sector chain can hold when
	// the size recorded by a damaged file is larger.
	unit := int64(s.r.sectorSize)
	if s.mini {
		unit = miniSectSize
	}
	size := min(s.size, int64(len(s.chain))*unit)
	buf := make([]byte, size)
	n, err := io.ReadFull(s, buf)
	if err != nil {
		return buf[:n], err
	}
	if size < s.size {
		return buf, io.ErrUnexpectedEOF
	}
	return buf, nil
}

func Open(src io.ReaderAt, size int64) (*Reader, error) {
	head := make([]byte, sectorSize512)
	if _, err := src.ReadAt(head, 0); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return nil, fmt.Errorf("%w: short header", ErrNotCompoundFile)
		}
		return nil, fmt.Errorf("cfb: reading header: %w", err)
	}

	if !bytes.Equal(head[:8], magic[:]) {
		return nil, fmt.Errorf("%w: bad signature", ErrNotCompoundFile)
	}

	if byteOrder.Uint16(head[0x1C:]) != 0xFFFE {
		return nil, fmt.Errorf("%w: unexpected byte order mark", ErrCorrupt)
	}

	r := &Reader{src: src, size: size, version: byteOrder.Uint16(head[0x1A:])}
	shift := byteOrder.Uint16(head[0x1E:])
	switch {
	case r.version == 3 && shift == 9:
		r.sectorSize = 512
	case r.version == 4 && shift == 12:
		r.sectorSize = 4096
	default:
		return nil, fmt.Errorf("%w: version %d / sector shift %d", ErrUnsupported, r.version, shift)
	}

	if byteOrder.Uint16(head[0x20:]) != 6 {
		return nil, fmt.Errorf("%w: unexpected mini sector shift", ErrUnsupported)
	}

	fatCount := int(byteOrder.Uint32(head[0x2C:]))
	dirStart := byteOrder.Uint32(head[0x30:])
	r.miniCutoff = uint64(byteOrder.Uint32(head[0x38:]))
	miniFatStart := byteOrder.Uint32(head[0x3C:])
	difatStart := byteOrder.Uint32(head[0x44:])
	difatCount := int(byteOrder.Uint32(head[0x48:]))

	maxSectors := int(size / int64(r.sectorSize))
	if fatCount < 0 || fatCount > maxSectors || difatCount < 0 || difatCount > maxSectors {
		return nil, fmt.Errorf("%w: sector counts larger than the file itself", ErrCorrupt)
	}

	fatLocators, err := r.collectFatLocators(head, fatCount, difatStart, difatCount, maxSectors)
	if err != nil {
		return nil, err
	}

	fatBytes := make([]byte, len(fatLocators)*r.sectorSize)
	if err := r.readSectors(fatLocators, fatBytes); err != nil {
		return nil, err
	}

	r.fat = make([]uint32, len(fatBytes)/4)
	for i := range r.fat {
		r.fat[i] = byteOrder.Uint32(fatBytes[4*i:])
	}

	dirBytes, err := r.readMetadataChain(dirStart)
	if err != nil {
		return nil, err
	}

	entries := parseDirentArray(dirBytes, r.version)
	if len(entries) == 0 || entries[0].kind != KindRoot {
		return nil, fmt.Errorf("%w: missing root entry", ErrCorrupt)
	}

	if miniFatStart != sectorEndOfChain && miniFatStart != sectorFree {
		raw, err := r.readMetadataChain(miniFatStart)
		if err != nil {
			return nil, err
		}

		r.miniFat = make([]uint32, len(raw)/4)
		for i := range r.miniFat {
			r.miniFat[i] = byteOrder.Uint32(raw[4*i:])
		}
	}

	root, err := r.buildTree(entries)
	if err != nil {
		return nil, err
	}

	r.Root = root

	if root.Size > 0 && root.startSec != sectorEndOfChain {
		chain, err := r.sectorChain(root.startSec, false, divRoundUp(int(root.Size), r.sectorSize))
		if err != nil {
			return nil, err
		}

		r.rootChain = chain
	}
	return r, nil
}

func (r *Reader) collectFatLocators(head []byte, fatCount int, difatStart uint32, difatCount, maxSectors int) ([]uint32, error) {
	var out []uint32
	for i := 0; i < headerFatSlots && len(out) < fatCount; i++ {
		out = append(out, byteOrder.Uint32(head[0x4C+4*i:]))
	}
	perSector := r.sectorSize/4 - 1
	s := difatStart
	for n := 0; s != sectorEndOfChain && s != sectorFree && len(out) < fatCount; n++ {
		if n > difatCount || n > maxSectors {
			return nil, fmt.Errorf("%w: DIFAT chain longer than declared", ErrCorrupt)
		}
		sec, err := r.sector(s)
		if err != nil {
			return nil, err
		}
		for i := 0; i < perSector && len(out) < fatCount; i++ {
			out = append(out, byteOrder.Uint32(sec[4*i:]))
		}
		s = byteOrder.Uint32(sec[4*perSector:])
	}
	if len(out) != fatCount {
		return nil, fmt.Errorf("%w: found %d FAT sectors, header declares %d", ErrCorrupt, len(out), fatCount)
	}
	return out, nil
}

type dirent struct {
	name               string
	kind               EntryKind
	left, right, child uint32
	clsid              CLSID
	stateBits          uint32
	created, modified  uint64
	start              uint32
	size               uint64
}

func parseDirentArray(data []byte, version uint16) []dirent {
	out := make([]dirent, len(data)/direntSize)
	for i := range out {
		out[i].parse(data[i*direntSize : (i+1)*direntSize])
		if version == 3 {
			out[i].size &= 0xFFFFFFFF // high 32 bits are undefined pre-v4
		}
	}
	return out
}

// decodeName decodes the UTF-16 name of an entry, directly when it is ASCII.
func decodeName(units []uint16) string {
	for _, u := range units {
		if u >= 0x80 {
			return string(utf16.Decode(units))
		}
	}

	var s strings.Builder
	s.Grow(len(units))
	for _, u := range units {
		s.WriteByte(byte(u))
	}
	return s.String()
}

func (d *dirent) parse(b []byte) {
	nameLen := min(int(byteOrder.Uint16(b[0x40:])), 64)
	var buf [32]uint16
	units := buf[:0]
	for i := 0; i+1 < nameLen; i += 2 {
		u := byteOrder.Uint16(b[i:])
		if u == 0 {
			break
		}
		units = append(units, u)
	}
	d.name = decodeName(units)
	d.kind = EntryKind(b[0x42])
	d.left = byteOrder.Uint32(b[0x44:])
	d.right = byteOrder.Uint32(b[0x48:])
	d.child = byteOrder.Uint32(b[0x4C:])
	copy(d.clsid[:], b[0x50:0x60])
	d.stateBits = byteOrder.Uint32(b[0x60:])
	d.created = byteOrder.Uint64(b[0x64:])
	d.modified = byteOrder.Uint64(b[0x6C:])
	d.start = byteOrder.Uint32(b[0x74:])
	d.size = byteOrder.Uint64(b[0x78:])
}

func (r *Reader) buildTree(flat []dirent) (*Entry, error) {
	seen := make([]bool, len(flat))
	var materialize func(id uint32) (*Entry, error)
	materialize = func(id uint32) (*Entry, error) {
		d := &flat[id]
		e := &Entry{
			Name: d.name, Kind: d.kind, CLSID: d.clsid, StateBits: d.stateBits,
			Created: filetimeToTime(d.created), Modified: filetimeToTime(d.modified),
			owner: r, startSec: d.start,
		}
		if d.kind == KindStream {
			e.Size = d.size
		}
		if d.kind == KindStorage || d.kind == KindRoot {
			var inorder func(id uint32) error
			inorder = func(id uint32) error {
				if id == noChild {
					return nil
				}

				if int(id) >= len(flat) || seen[id] {
					return fmt.Errorf("%w: directory tree is broken or cyclic", ErrCorrupt)
				}

				seen[id] = true
				if err := inorder(flat[id].left); err != nil {
					return err
				}

				child, err := materialize(id)
				if err != nil {
					return err
				}

				e.Children = append(e.Children, child)
				return inorder(flat[id].right)
			}

			if err := inorder(d.child); err != nil {
				return nil, err
			}
		}
		return e, nil
	}
	seen[0] = true
	root, err := materialize(0)
	if err != nil {
		return nil, err
	}
	root.Size = flat[0].size
	return root, nil
}

func (r *Reader) sector(n uint32) ([]byte, error) {
	if n > sectorMaxRegular {
		return nil, fmt.Errorf("%w: sector number %#x is a reserved value", ErrCorrupt, n)
	}

	off := (int64(n) + 1) * int64(r.sectorSize)
	if off+int64(r.sectorSize) > r.size {
		return nil, fmt.Errorf("%w: sector %d is beyond the end of the file", ErrCorrupt, n)
	}

	buf := make([]byte, r.sectorSize)
	if _, err := r.src.ReadAt(buf, off); err != nil {
		return nil, fmt.Errorf("cfb: reading sector %d: %w", n, err)
	}

	return buf, nil
}

func (r *Reader) readMetadataChain(start uint32) ([]byte, error) {
	var chain []uint32
	s := start
	for n := 0; s != sectorEndOfChain; n++ {
		// A chain holding more bytes than the file must revisit a sector.
		if int(s) >= len(r.fat) || n > len(r.fat) || int64(len(chain))*int64(r.sectorSize) >= r.size {
			return nil, fmt.Errorf("%w: sector chain is broken or cyclic", ErrCorrupt)
		}

		chain = append(chain, s)
		s = r.fat[s]
	}

	out := make([]byte, len(chain)*r.sectorSize)
	if err := r.readSectors(chain, out); err != nil {
		return nil, err
	}
	return out, nil
}

// readSectors reads the regular sectors of a chain into dst, which holds
// them all, with one read for each run of consecutive sectors.
func (r *Reader) readSectors(chain []uint32, dst []byte) error {
	for i := 0; i < len(chain); {
		run := 1
		for i+run < len(chain) && chain[i+run] == chain[i]+uint32(run) {
			run++
		}
		if err := r.readRun(chain[i], run, dst[i*r.sectorSize:(i+run)*r.sectorSize]); err != nil {
			return err
		}
		i += run
	}
	return nil
}

// readRun reads count consecutive sectors from sector first into dst, with
// the checks of sector.
func (r *Reader) readRun(first uint32, count int, dst []byte) error {
	last := uint64(first) + uint64(count) - 1
	if last > sectorMaxRegular {
		return fmt.Errorf("%w: sector number %#x is a reserved value", ErrCorrupt, last)
	}

	off := (int64(first) + 1) * int64(r.sectorSize)
	if (int64(last)+2)*int64(r.sectorSize) > r.size {
		return fmt.Errorf("%w: sector %d is beyond the end of the file", ErrCorrupt, last)
	}

	if _, err := r.src.ReadAt(dst, off); err != nil {
		return fmt.Errorf("cfb: reading sector %d: %w", first, err)
	}
	return nil
}

// miniStream returns the mini stream, which it reads whole the first time.
func (r *Reader) miniStream() ([]byte, error) {
	r.miniOnce.Do(func() {
		data := make([]byte, len(r.rootChain)*r.sectorSize)
		if r.miniErr = r.readSectors(r.rootChain, data); r.miniErr == nil {
			r.miniData = data
		}
	})
	return r.miniData, r.miniErr
}

func (r *Reader) sectorChain(start uint32, mini bool, limit int) ([]uint32, error) {
	fat := r.fat
	if mini {
		fat = r.miniFat
	}

	// A chain longer than the table, or than the file has sectors, must
	// revisit a sector.
	maxLen := len(fat)
	if !mini {
		maxLen = min(maxLen, int(r.size/int64(r.sectorSize)))
	}

	var out []uint32
	s := start
	for n := 0; s != sectorEndOfChain && len(out) < limit; n++ {
		if int(s) >= len(fat) || n > maxLen {
			return nil, fmt.Errorf("%w: sector chain is broken or cyclic", ErrCorrupt)
		}
		out = append(out, s)
		s = fat[s]
	}
	return out, nil
}

// Stream reads the content of a stream entry. It implements [io.Reader],
// [io.ReaderAt] and [io.Seeker], fetching sectors on demand.
//
// A Stream is not safe for concurrent use; open one per goroutine.
type Stream struct {
	r     *Reader
	mini  bool
	chain []uint32
	size  int64
	pos   int64

	// secBuf caches the most recently read regular sector, so sequential
	// reads within the same sector don't re-read it
	secBuf   []byte
	secID    uint32
	secValid bool
}

func (s *Stream) Size() int64 {
	return s.size
}

// ReadAt implements io.ReaderAt.
func (s *Stream) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("cfb: negative read offset")
	}

	if off >= s.size {
		return 0, io.EOF
	}

	want := len(p)
	if off+int64(want) > s.size {
		p = p[:s.size-off]
	}

	unit := int64(s.r.sectorSize)
	if s.mini {
		unit = miniSectSize
	}

	n := 0
	for n < len(p) {
		cur := off + int64(n)
		idx := int(cur / unit)
		if idx >= len(s.chain) {
			return n, io.ErrUnexpectedEOF
		}
		within := int(cur % unit)
		if !s.mini && within == 0 && len(p)-n >= int(unit) {
			// Whole sectors: each run of consecutive ones is read at once,
			// straight into p.
			run, most := 1, (len(p)-n)/int(unit)
			for run < most && idx+run < len(s.chain) && s.chain[idx+run] == s.chain[idx]+uint32(run) {
				run++
			}
			if err := s.r.readRun(s.chain[idx], run, p[n:n+run*int(unit)]); err != nil {
				return n, err
			}
			n += run * int(unit)
			continue
		}
		toRead := int(unit) - within
		if rem := len(p) - n; toRead > rem {
			toRead = rem
		}

		var src []byte
		var err error
		if s.mini {
			src, err = s.miniSectorBytes(s.chain[idx], within)
		} else {
			src, err = s.regularSectorBytes(s.chain[idx], within)
		}
		if err != nil {
			return n, err
		}

		if toRead > len(src) {
			toRead = len(src)
		}
		if toRead == 0 {
			break
		}
		copy(p[n:n+toRead], src[:toRead])
		n += toRead
	}
	if n < want {
		if n < len(p) {
			return n, io.ErrUnexpectedEOF
		}
		return n, io.EOF
	}
	return n, nil
}

// Read implements io.Reader, advancing the stream's cursor.
func (s *Stream) Read(p []byte) (int, error) {
	n, err := s.ReadAt(p, s.pos)
	s.pos += int64(n)
	if err == io.EOF && n > 0 {
		err = nil
	}
	return n, err
}

// Seek implements io.Seeker.
func (s *Stream) Seek(offset int64, whence int) (int64, error) {
	var pos int64
	switch whence {
	case io.SeekStart:
		pos = offset
	case io.SeekCurrent:
		pos = s.pos + offset
	case io.SeekEnd:
		pos = s.size + offset
	default:
		return 0, fmt.Errorf("cfb: invalid whence")
	}
	if pos < 0 {
		return 0, fmt.Errorf("cfb: negative seek position")
	}
	s.pos = pos
	return pos, nil
}

func (s *Stream) regularSectorBytes(id uint32, from int) ([]byte, error) {
	if s.secValid && s.secID == id {
		return s.secBuf[from:], nil
	}
	buf, err := s.r.sector(id)
	if err != nil {
		return nil, err
	}
	s.secBuf, s.secID, s.secValid = buf, id, true
	return buf[from:], nil
}

func (s *Stream) miniSectorBytes(miniID uint32, within int) ([]byte, error) {
	byteOff := int64(miniID)*miniSectSize + int64(within)
	mainIdx := int(byteOff / int64(s.r.sectorSize))
	if mainIdx >= len(s.r.rootChain) {
		return nil, fmt.Errorf("%w: mini sector %d is beyond the mini stream container", ErrCorrupt, miniID)
	}
	mini, err := s.r.miniStream()
	if err != nil {
		return nil, err
	}
	end := (byteOff/miniSectSize + 1) * miniSectSize
	return mini[byteOff:end], nil
}
