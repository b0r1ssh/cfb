package cfb

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"reflect"
	"testing"
)

func minimalValidFile(t *testing.T) []byte {
	t.Helper()

	var buf bytes.Buffer
	if _, err := NewRoot().WriteTo(&buf); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	return buf.Bytes()
}

func TestOpenRejectsGarbage(t *testing.T) {
	t.Parallel()

	_, err := Open(bytes.NewReader(make([]byte, 512)), 512)
	if err == nil {
		t.Fatal("expected an error for a non-CFB file")
	}
}

func TestOpenRejectsShortHeader(t *testing.T) {
	t.Parallel()

	short := make([]byte, 100) // shorter than one 512-byte sector
	if _, err := Open(bytes.NewReader(short), int64(len(short))); err == nil {
		t.Fatal("expected an error for a file shorter than one header sector")
	}
}

func TestOpenHeaderValidation(t *testing.T) {
	t.Parallel()

	base := minimalValidFile(t)

	cases := []struct {
		name  string
		patch func(b []byte)
	}{
		{"bad signature", func(b []byte) { b[0] = 0x00 }},
		{"bad byte order mark", func(b []byte) { byteOrder.PutUint16(b[0x1C:], 0) }},
		{"unsupported version/shift combination", func(b []byte) { byteOrder.PutUint16(b[0x1E:], 10) }},
		{"bad mini sector shift", func(b []byte) { byteOrder.PutUint16(b[0x20:], 5) }},
		{"FAT sector count beyond the file size", func(b []byte) { byteOrder.PutUint32(b[0x2C:], 0xFFFFFFF0) }},
		{"DIFAT sector count beyond the file size", func(b []byte) { byteOrder.PutUint32(b[0x48:], 0xFFFFFFF0) }},
		{"missing root entry", func(b []byte) {
			dirStart := byteOrder.Uint32(b[0x30:])
			off := (int64(dirStart) + 1) * sectorSize512
			b[off+0x42] = byte(KindStorage) // first directory entry must be the root
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := append([]byte(nil), base...)
			c.patch(b)
			if _, err := Open(bytes.NewReader(b), int64(len(b))); err == nil {
				t.Fatalf("expected Open to reject a file with: %s", c.name)
			}
		})
	}
}

func TestCollectFatLocatorsRejectsChainLongerThanDeclared(t *testing.T) {
	t.Parallel()

	const perSector = sectorSize512/4 - 1           // 127 locators per DIFAT sector
	const fatCount = headerFatSlots + perSector + 1 // more than one full DIFAT sector can declare

	buf := make([]byte, fatCount*sectorSize512) // big enough that the size bound itself passes
	copy(buf[:8], magic[:])
	byteOrder.PutUint16(buf[0x1A:], 3)      // version 3
	byteOrder.PutUint16(buf[0x1C:], 0xFFFE) // byte order mark
	byteOrder.PutUint16(buf[0x1E:], 9)      // sector shift -> 512-byte sectors
	byteOrder.PutUint16(buf[0x20:], 6)      // mini sector shift
	byteOrder.PutUint32(buf[0x2C:], uint32(fatCount))
	byteOrder.PutUint32(buf[0x44:], 0) // DIFAT chain starts at sector 0
	byteOrder.PutUint32(buf[0x48:], 0) // zero DIFAT sectors

	sec0 := buf[sectorSize512 : 2*sectorSize512]
	byteOrder.PutUint32(sec0[sectorSize512-4:], 1)

	if _, err := Open(bytes.NewReader(buf), int64(len(buf))); err == nil {
		t.Fatal("expected Open to reject a DIFAT chain longer than declared")
	}
}

func TestReadMetadataChainDetectsCycle(t *testing.T) {
	t.Parallel()

	buf := minimalValidFile(t)
	head := buf[:sectorSize512]
	dirStart := byteOrder.Uint32(head[0x30:])
	fatStart := byteOrder.Uint32(head[0x4C:]) // first FAT sector, from the header's inline locators

	fatSectorOffset := (int64(fatStart) + 1) * sectorSize512
	entryOffset := fatSectorOffset + int64(dirStart)*4
	byteOrder.PutUint32(buf[entryOffset:], dirStart) // point the dir chain back at itself

	if _, err := Open(bytes.NewReader(buf), int64(len(buf))); err == nil {
		t.Fatal("expected Open to detect the cyclic directory chain")
	}
}

func TestSectorChainDetectsCycle(t *testing.T) {
	t.Parallel()

	root := NewRoot()
	data := payload(5000, 9) // large enough to need several regular sectors
	if err := root.AddStream("Data", data); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if _, err := root.WriteTo(&buf); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()

	r, err := Open(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	startSec := r.Root.Find("Data").startSec

	head := raw[:sectorSize512]
	fatStart := byteOrder.Uint32(head[0x4C:])
	fatSectorOffset := (int64(fatStart) + 1) * sectorSize512
	entryOffset := fatSectorOffset + int64(startSec)*4

	corrupted := append([]byte(nil), raw...)
	byteOrder.PutUint32(corrupted[entryOffset:], 0xFFFFFFF0)

	r2, err := Open(bytes.NewReader(corrupted), int64(len(corrupted)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r2.Root.Find("Data").Open(); err == nil {
		t.Fatal("expected Entry.Open to detect the broken FAT chain")
	}
}

func TestSectorRejectsReservedAndOutOfRangeNumbers(t *testing.T) {
	t.Parallel()

	r := writeAndOpen(t, NewRoot())
	if _, err := r.sector(sectorDIFAT); err == nil {
		t.Fatal("expected an error for a reserved sector number")
	}
	beyondEOF := uint32(r.size / int64(r.sectorSize))
	if _, err := r.sector(beyondEOF); err == nil {
		t.Fatal("expected an error for a sector beyond the end of the file")
	}
}

func TestEntryIsRootAndFindMiss(t *testing.T) {
	t.Parallel()

	root := NewRoot()
	if err := root.AddStream("Only", nil); err != nil {
		t.Fatal(err)
	}
	r := writeAndOpen(t, root)
	if !r.Root.IsRoot() {
		t.Fatal("Root.IsRoot() = false, want true")
	}
	if r.Root.Find("Only").IsRoot() {
		t.Fatal("a stream entry reported IsRoot() = true")
	}
	if e := r.Root.Find("Missing"); e != nil {
		t.Fatalf("Find(%q) = %v, want nil", "Missing", e)
	}
}

func TestEntryOpenAndBytesOnNonStreamFail(t *testing.T) {
	t.Parallel()

	root := NewRoot()
	if _, err := root.AddStorage("Sub"); err != nil {
		t.Fatal(err)
	}
	r := writeAndOpen(t, root)

	if _, err := r.Root.Open(); err == nil {
		t.Fatal("Open() on the root storage should fail")
	}
	if _, err := r.Root.Bytes(); err == nil {
		t.Fatal("Bytes() on the root storage should fail")
	}
	sub := r.Root.Find("Sub")
	if _, err := sub.Open(); err == nil {
		t.Fatal("Open() on a non-root storage entry should fail")
	}
}

func TestStreamReadAtAndSeek(t *testing.T) {
	t.Parallel()

	root := NewRoot()
	data := payload(5000, 42) // spans several regular sectors
	if err := root.AddStream("Data", data); err != nil {
		t.Fatal(err)
	}
	r := writeAndOpen(t, root)
	s, err := r.Root.Find("Data").Open()
	if err != nil {
		t.Fatal(err)
	}
	if s.Size() != int64(len(data)) {
		t.Fatalf("Size() = %d, want %d", s.Size(), len(data))
	}

	for _, off := range []int64{0, 1, 511, 512, 513, 4999} {
		buf := make([]byte, 3)
		n, err := s.ReadAt(buf, off)
		if err != nil && err != io.EOF {
			t.Fatalf("ReadAt(off=%d): %v", off, err)
		}
		want := data[off : off+int64(n)]
		if !bytes.Equal(buf[:n], want) {
			t.Fatalf("ReadAt(off=%d) = % X, want % X", off, buf[:n], want)
		}
	}

	// Seek + sequential Read must reproduce the whole stream.
	if _, err := s.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(s)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("sequential read: got %d bytes, want %d", len(got), len(data))
	}
}

func TestOpenErrorsMatchSentinels(t *testing.T) {
	t.Parallel()

	base := minimalValidFile(t)
	patched := func(patch func(b []byte)) []byte {
		b := append([]byte(nil), base...)
		patch(b)
		return b
	}

	cases := []struct {
		name string
		file []byte
		want error
	}{
		{"short header", make([]byte, 100), ErrNotCompoundFile},
		{"bad signature", patched(func(b []byte) { b[0] = 0 }), ErrNotCompoundFile},
		{"unknown version", patched(func(b []byte) { byteOrder.PutUint16(b[0x1A:], 5) }), ErrUnsupported},
		{"directory start beyond the FAT", patched(func(b []byte) { byteOrder.PutUint32(b[0x30:], 0x00FFFFFF) }), ErrCorrupt},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Open(bytes.NewReader(c.file), int64(len(c.file)))
			if !errors.Is(err, c.want) {
				t.Fatalf("Open error = %v, want one matching %v", err, c.want)
			}
		})
	}
}

// treeForNavigation builds Root{ A{ B{ Leaf } Top } Z } for the Lookup and
// Walk tests.
func treeForNavigation(t *testing.T) *Reader {
	t.Helper()

	root := NewRoot()
	a, err := root.AddStorage("A")
	if err != nil {
		t.Fatal(err)
	}
	b, err := a.AddStorage("B")
	if err != nil {
		t.Fatal(err)
	}
	if err := b.AddStream("Leaf", []byte("leaf")); err != nil {
		t.Fatal(err)
	}
	if err := a.AddStream("Top", []byte("top")); err != nil {
		t.Fatal(err)
	}
	if err := root.AddStream("Z", nil); err != nil {
		t.Fatal(err)
	}
	return writeAndOpen(t, root)
}

func TestEntryLookup(t *testing.T) {
	t.Parallel()

	r := treeForNavigation(t)

	leaf := r.Root.Lookup("a/B/leaf") // elements match case-insensitively
	if leaf == nil || leaf.Name != "Leaf" {
		t.Fatalf("Lookup(a/B/leaf) = %v, want the Leaf stream", leaf)
	}
	if got := r.Root.Lookup("/A//B/"); got == nil || got.Name != "B" {
		t.Fatalf("Lookup with empty elements = %v, want storage B", got)
	}
	if got := r.Root.Lookup(""); got != r.Root {
		t.Fatalf("Lookup of the empty path = %v, want the receiver", got)
	}
	for _, p := range []string{"Missing", "A/Missing", "A/Top/Below"} {
		if got := r.Root.Lookup(p); got != nil {
			t.Fatalf("Lookup(%q) = %v, want nil", p, got)
		}
	}
}

func TestEntryWalk(t *testing.T) {
	t.Parallel()

	r := treeForNavigation(t)
	collect := func(skip string, stop error) ([]string, error) {
		var paths []string
		err := r.Root.Walk(func(p string, e *Entry) error {
			paths = append(paths, p)
			if p == skip {
				return fs.SkipDir
			}
			if stop != nil && p == "A/B" {
				return stop
			}
			if r.Root.Lookup(p) != e {
				t.Errorf("Lookup(%q) does not return the walked entry", p)
			}
			return nil
		})
		return paths, err
	}

	got, err := collect("", nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"A", "A/B", "A/B/Leaf", "A/Top", "Z"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Walk visited %v, want %v", got, want)
	}

	got, err = collect("A/B", nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"A", "A/B", "A/Top", "Z"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Walk with SkipDir visited %v, want %v", got, want)
	}

	stop := errors.New("stop")
	got, err = collect("", stop)
	if err != stop {
		t.Fatalf("Walk error = %v, want the callback's error", err)
	}
	if want := []string{"A", "A/B"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Walk visited %v before stopping, want %v", got, want)
	}
}

// TestOpenVersion4 reads a hand-assembled 4096-byte-sector file, since the
// writer only produces version 3.
func TestOpenVersion4(t *testing.T) {
	t.Parallel()

	const sec = 4096
	data := payload(5000, 11) // two sectors, the second one partly used

	head := make([]byte, sec)
	copy(head, magic[:])
	byteOrder.PutUint16(head[0x1A:], 4)      // major version
	byteOrder.PutUint16(head[0x1C:], 0xFFFE) // byte order mark
	byteOrder.PutUint16(head[0x1E:], 12)     // sector shift -> 4096-byte sectors
	byteOrder.PutUint16(head[0x20:], 6)      // mini sector shift
	byteOrder.PutUint32(head[0x28:], 1)      // directory sectors
	byteOrder.PutUint32(head[0x2C:], 1)      // FAT sectors
	byteOrder.PutUint32(head[0x30:], 1)      // directory starts at sector 1
	byteOrder.PutUint32(head[0x38:], miniStreamCap)
	byteOrder.PutUint32(head[0x3C:], sectorEndOfChain) // no mini FAT
	byteOrder.PutUint32(head[0x44:], sectorEndOfChain) // no DIFAT
	for i := range headerFatSlots {
		byteOrder.PutUint32(head[0x4C+4*i:], sectorFree)
	}
	byteOrder.PutUint32(head[0x4C:], 0) // the FAT is sector 0

	fat := encodeU32Table([]uint32{sectorFAT, sectorEndOfChain, 3, sectorEndOfChain}, sec/4)
	dir := encodeDirentArray([]*plannedEntry{
		{name: "Root Entry", kind: KindRoot, color: nodeColorBlack, left: noChild, right: noChild, child: 1, start: sectorEndOfChain},
		{name: "Data", kind: KindStream, color: nodeColorBlack, left: noChild, right: noChild, child: noChild, start: 2, size: uint64(len(data))},
	}, sec/direntSize)

	file := bytes.Join([][]byte{head, fat, dir, data, make([]byte, 2*sec-len(data))}, nil)

	r, err := Open(bytes.NewReader(file), int64(len(file)))
	if err != nil {
		t.Fatal(err)
	}
	if r.Version() != 4 || r.SectorSize() != sec {
		t.Fatalf("Version, SectorSize = %d, %d; want 4, %d", r.Version(), r.SectorSize(), sec)
	}
	got, err := r.Root.Find("Data").Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("got %d bytes that differ from the %d written", len(got), len(data))
	}
}

func TestStreamSeekVariants(t *testing.T) {
	t.Parallel()

	root := NewRoot()
	data := payload(100, 3)
	if err := root.AddStream("Data", data); err != nil {
		t.Fatal(err)
	}
	r := writeAndOpen(t, root)
	s, err := r.Root.Find("Data").Open()
	if err != nil {
		t.Fatal(err)
	}

	if pos, err := s.Seek(10, io.SeekStart); err != nil || pos != 10 {
		t.Fatalf("Seek(10, SeekStart) = %d, %v", pos, err)
	}
	if pos, err := s.Seek(5, io.SeekCurrent); err != nil || pos != 15 {
		t.Fatalf("Seek(5, SeekCurrent) = %d, %v", pos, err)
	}
	if pos, err := s.Seek(-10, io.SeekEnd); err != nil || pos != int64(len(data))-10 {
		t.Fatalf("Seek(-10, SeekEnd) = %d, %v", pos, err)
	}
	if _, err := s.Seek(-1, io.SeekStart); err == nil {
		t.Fatal("expected an error seeking to a negative position")
	}
	if _, err := s.Seek(0, 99); err == nil {
		t.Fatal("expected an error for an invalid whence value")
	}
}

func TestStreamReadAtNegativeOffset(t *testing.T) {
	t.Parallel()

	root := NewRoot()
	if err := root.AddStream("Data", payload(10, 1)); err != nil {
		t.Fatal(err)
	}
	r := writeAndOpen(t, root)
	s, err := r.Root.Find("Data").Open()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadAt(make([]byte, 1), -1); err == nil {
		t.Fatal("expected an error for a negative ReadAt offset")
	}
}

func TestStreamSmallerThanMiniCutoffOutOfRangeMiniSector(t *testing.T) {
	t.Parallel()

	root := NewRoot()
	if err := root.AddStream("Tiny", payload(10, 5)); err != nil {
		t.Fatal(err)
	}
	r := writeAndOpen(t, root)
	s, err := r.Root.Find("Tiny").Open()
	if err != nil {
		t.Fatal(err)
	}
	s.chain = append(s.chain, 1<<20)
	s.size += miniSectSize
	if _, err := io.ReadAll(s); err == nil {
		t.Fatal("expected an error reading a mini sector beyond the mini stream container")
	}
}
