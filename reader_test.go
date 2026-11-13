package cfb

import (
	"bytes"
	"io"
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
	_, err := Open(bytes.NewReader(make([]byte, 512)), 512)
	if err == nil {
		t.Fatal("expected an error for a non-CFB file")
	}
}

func TestOpenRejectsShortHeader(t *testing.T) {
	short := make([]byte, 100) // shorter than one 512-byte sector
	if _, err := Open(bytes.NewReader(short), int64(len(short))); err == nil {
		t.Fatal("expected an error for a file shorter than one header sector")
	}
}

func TestOpenHeaderValidation(t *testing.T) {
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

func TestStreamSeekVariants(t *testing.T) {
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
