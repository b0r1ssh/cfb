package cfb

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestRoundTripFlatStreams(t *testing.T) {
	t.Parallel()

	root := NewRoot()
	small := payload(100, 1)
	big := payload(10_000, 2)
	empty := []byte{}
	if err := root.AddStream("Small", small); err != nil {
		t.Fatal(err)
	}
	if err := root.AddStream("Big", big); err != nil {
		t.Fatal(err)
	}
	if err := root.AddStream("Empty", empty); err != nil {
		t.Fatal(err)
	}

	r := writeAndOpen(t, root)
	if len(r.Root.Children) != 3 {
		t.Fatalf("got %d children, want 3", len(r.Root.Children))
	}
	for name, want := range map[string][]byte{"Small": small, "Big": big, "Empty": empty} {
		e := r.Root.Find(name)
		if e == nil {
			t.Fatalf("entry %q not found", name)
		}
		got, err := e.Bytes()
		if err != nil {
			t.Fatalf("Bytes(%q): %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("content of %q: got %d bytes, want %d", name, len(got), len(want))
		}
	}
}

func TestRoundTripNestedStorages(t *testing.T) {
	t.Parallel()

	root := NewRoot()
	root.SetCLSID(MustParseCLSID("00020D0B-0000-0000-C000-000000000046"))
	sub, err := root.AddStorage("Sub")
	if err != nil {
		t.Fatal(err)
	}
	if err := sub.AddStream("Leaf", []byte("hello")); err != nil {
		t.Fatal(err)
	}
	// Enough siblings to exercise the balanced tree builder across levels.
	for i := range 20 {
		if err := root.AddStream(string(rune('A'+i)), payload(i+1, int64(i))); err != nil {
			t.Fatal(err)
		}
	}

	r := writeAndOpen(t, root)
	if got := r.Root.CLSID.String(); got != "00020D0B-0000-0000-C000-000000000046" {
		t.Fatalf("CLSID = %s", got)
	}
	subEntry := r.Root.Find("Sub")
	if subEntry == nil || !subEntry.IsStorage() && !subEntry.IsRoot() {
		t.Fatalf("Sub storage not found")
	}
	leaf := subEntry.Find("Leaf")
	if leaf == nil {
		t.Fatalf("Leaf stream not found")
	}
	got, err := leaf.Bytes()
	if err != nil || string(got) != "hello" {
		t.Fatalf("Leaf content = %q, %v", got, err)
	}
	if len(r.Root.Children) != 21 { // Sub + 20 letters
		t.Fatalf("got %d root children, want 21", len(r.Root.Children))
	}
}

func TestStreamSmallerThanMiniCutoff(t *testing.T) {
	t.Parallel()

	root := NewRoot()
	data := payload(50, 7) // lives in the mini stream
	if err := root.AddStream("Tiny", data); err != nil {
		t.Fatal(err)
	}
	// Add enough other mini streams that the mini stream container spans
	// more than one regular sector, exercising mini-to-regular resolution.
	for i := range 50 {
		if err := root.AddStream(string(rune('a'+i))+"x", payload(100, int64(100+i))); err != nil {
			t.Fatal(err)
		}
	}
	r := writeAndOpen(t, root)
	e := r.Root.Find("Tiny")
	got, err := e.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("mini stream content mismatch")
	}
}

func TestChildrenAreSortedCaseInsensitively(t *testing.T) {
	t.Parallel()

	root := NewRoot()
	// Same length, so length-first ordering (see the test below) can't mask
	// a case-insensitive comparison bug.
	for _, name := range []string{"Pear", "plum", "Kiwi", "lime"} {
		if err := root.AddStream(name, nil); err != nil {
			t.Fatal(err)
		}
	}
	r := writeAndOpen(t, root)

	got := make([]string, len(r.Root.Children))
	for i, c := range r.Root.Children {
		got[i] = c.Name
	}
	want := []string{"Kiwi", "lime", "Pear", "plum"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if !strings.EqualFold(got[i], want[i]) {
			t.Fatalf("children order = %v, want (case-insensitively) %v", got, want)
		}
	}
}

func TestChildrenAreSortedByLengthBeforeValue(t *testing.T) {
	t.Parallel()

	root := NewRoot()
	for _, name := range []string{"banana", "Apple", "cherry", "apricot"} {
		if err := root.AddStream(name, nil); err != nil {
			t.Fatal(err)
		}
	}
	r := writeAndOpen(t, root)

	got := make([]string, len(r.Root.Children))
	for i, c := range r.Root.Children {
		got[i] = c.Name
	}
	want := []string{"Apple", "banana", "cherry", "apricot"} // 5, 6, 6, 7 UTF-16 units
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if !strings.EqualFold(got[i], want[i]) {
			t.Fatalf("children order = %v, want %v", got, want)
		}
	}
}

func TestDuplicateNameRejected(t *testing.T) {
	t.Parallel()

	root := NewRoot()
	if err := root.AddStream("X", nil); err != nil {
		t.Fatal(err)
	}
	if err := root.AddStream("x", nil); err == nil { // names compare case-insensitively
		t.Fatal("expected a duplicate name error")
	}
}

func TestAddStorageDuplicateNameRejected(t *testing.T) {
	t.Parallel()

	root := NewRoot()
	if _, err := root.AddStorage("Sub"); err != nil {
		t.Fatal(err)
	}
	if _, err := root.AddStorage("sub"); err == nil { // names compare case-insensitively
		t.Fatal("expected a duplicate name error")
	}
	if err := root.AddStream("SUB", nil); err == nil {
		t.Fatal("expected a duplicate name error across storages and streams")
	}
}

func TestAddStreamNameValidation(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		reason string
	}{
		{"", "empty name"},
		{strings.Repeat("a", 32), "name longer than 31 UTF-16 code units"},
		{"a/b", "name contains '/'"},
		{"a\\b", "name contains '\\'"},
		{"a:b", "name contains ':'"},
		{"a!b", "name contains '!'"},
	}
	for _, c := range cases {
		root := NewRoot()
		if err := root.AddStream(c.name, nil); err == nil {
			t.Errorf("AddStream(%q): expected an error (%s), got nil", c.name, c.reason)
		}
	}

	// The boundary itself (31 units) must be accepted.
	root := NewRoot()
	if err := root.AddStream(strings.Repeat("a", 31), nil); err != nil {
		t.Fatalf("AddStream with a 31-unit name: %v", err)
	}
}

func TestWriteToRequiresRoot(t *testing.T) {
	t.Parallel()

	root := NewRoot()
	sub, err := root.AddStorage("Sub")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := sub.WriteTo(&buf); err == nil {
		t.Fatal("expected WriteTo on a non-root storage to fail")
	}
}

func TestSectorAllocatorRequiresDifat(t *testing.T) {
	t.Parallel()

	a := &sectorAllocator{fat: make([]uint32, 20_000)}
	fatStart, fatSectors, difatStart, difatSectors := a.layoutFatAndDifat()

	if fatSectors <= headerFatSlots {
		t.Fatalf("fatSectors = %d, want > %d to require a DIFAT", fatSectors, headerFatSlots)
	}
	if difatSectors == 0 {
		t.Fatal("expected at least one DIFAT sector to be allocated")
	}
	if got := a.fat[fatStart]; got != sectorFAT {
		t.Fatalf("a.fat[fatStart] = %#x, want sectorFAT", got)
	}
	if got := a.fat[difatStart]; got != sectorDIFAT {
		t.Fatalf("a.fat[difatStart] = %#x, want sectorDIFAT", got)
	}
	const u32PerSector = sectorSize512 / 4
	if len(a.fat)%u32PerSector != 0 {
		t.Fatalf("len(a.fat) = %d is not a whole number of FAT sectors", len(a.fat))
	}
	if len(a.fat) != fatSectors*u32PerSector {
		t.Fatalf("len(a.fat) = %d, want %d (fatSectors * entries per sector)", len(a.fat), fatSectors*u32PerSector)
	}
}

func TestEncodeDifat(t *testing.T) {
	t.Parallel()

	const fatStart = 1000
	const fatSectors = 250 // 141 sectors beyond the header's 109 inline slots
	const difatStart = 2000
	const difatSectors = 2 // 127 slots/sector: ceil(141/127) = 2

	out := encodeDifat(fatStart, fatSectors, difatStart, difatSectors)
	if len(out) != difatSectors*sectorSize512 {
		t.Fatalf("len(out) = %d, want %d", len(out), difatSectors*sectorSize512)
	}

	const perSector = sectorSize512/4 - 1 // last slot of each sector chains onward
	wantOverflow := fatSectors - headerFatSlots
	var locators []uint32
	for d := 0; d < difatSectors; d++ {
		sec := out[d*sectorSize512 : (d+1)*sectorSize512]
		for j := 0; j < perSector; j++ {
			v := byteOrder.Uint32(sec[4*j:])
			if v != sectorFree {
				locators = append(locators, v)
			}
		}
		next := byteOrder.Uint32(sec[perSector*4:])
		if d < difatSectors-1 {
			if want := uint32(difatStart + d + 1); next != want {
				t.Fatalf("sector %d chains to %#x, want %#x", d, next, want)
			}
		} else if next != sectorEndOfChain {
			t.Fatalf("last DIFAT sector chains to %#x, want sectorEndOfChain", next)
		}
	}

	if len(locators) != wantOverflow {
		t.Fatalf("got %d overflow locators, want %d", len(locators), wantOverflow)
	}
	for i, v := range locators {
		if want := uint32(fatStart + headerFatSlots + i); v != want {
			t.Fatalf("locator %d = %#x, want %#x", i, v, want)
		}
	}
}

func TestRoundTripStorageMetadata(t *testing.T) {
	t.Parallel()

	// FILETIME has 100 ns resolution, so pick times that survive it exactly.
	created := time.Date(1999, 12, 31, 23, 59, 59, 123_456_700, time.UTC)
	modified := time.Date(2026, 11, 14, 20, 0, 0, 0, time.FixedZone("CET", 3600))

	root := NewRoot()
	root.SetTimes(created, modified)
	root.SetStateBits(0xA5A5A5A5)
	sub, err := root.AddStorage("Sub")
	if err != nil {
		t.Fatal(err)
	}
	sub.SetTimes(created, modified)
	sub.SetStateBits(7)
	if _, err := root.AddStorage("Unset"); err != nil {
		t.Fatal(err)
	}
	if err := root.AddStream("Stream", []byte("x")); err != nil {
		t.Fatal(err)
	}

	r := writeAndOpen(t, root)

	if !r.Root.Created.IsZero() {
		t.Fatalf("root Created = %v, want zero: the format forbids a root creation time", r.Root.Created)
	}
	if !r.Root.Modified.Equal(modified) || r.Root.StateBits != 0xA5A5A5A5 {
		t.Fatalf("root Modified, StateBits = %v, %#x", r.Root.Modified, r.Root.StateBits)
	}

	got := r.Root.Find("Sub")
	if !got.Created.Equal(created) || !got.Modified.Equal(modified) || got.StateBits != 7 {
		t.Fatalf("Sub Created, Modified, StateBits = %v, %v, %d", got.Created, got.Modified, got.StateBits)
	}
	if got.Modified.Location() != time.UTC {
		t.Fatalf("Modified location = %v, want UTC", got.Modified.Location())
	}

	for _, name := range []string{"Unset", "Stream"} {
		e := r.Root.Find(name)
		if !e.Created.IsZero() || !e.Modified.IsZero() || e.StateBits != 0 {
			t.Fatalf("%s has metadata that was never set: %v, %v, %d", name, e.Created, e.Modified, e.StateBits)
		}
	}
}

func TestBuildHeaderDifatField(t *testing.T) {
	t.Parallel()

	h := headerFields{fatSectors: 5, dirStart: 1, miniFatStart: sectorEndOfChain, fatStart: 2}

	h.difatStart, h.difatSectors = 42, 3
	b := buildHeader(h)
	if got := byteOrder.Uint32(b[0x44:]); got != 42 {
		t.Fatalf("difat start = %d, want 42", got)
	}
	if got := byteOrder.Uint32(b[0x48:]); got != 3 {
		t.Fatalf("difat sector count = %d, want 3", got)
	}

	h.difatSectors = 0
	b = buildHeader(h)
	if got := byteOrder.Uint32(b[0x44:]); got != sectorEndOfChain {
		t.Fatalf("difat start = %#x, want sectorEndOfChain when there are no DIFAT sectors", got)
	}
	if got := byteOrder.Uint32(b[0x48:]); got != 0 {
		t.Fatalf("difat sector count = %d, want 0", got)
	}
}

type closeCounter struct {
	io.Reader
	closed *int
}

func (c closeCounter) Close() error {
	*c.closed++
	return nil
}

func TestAddStreamFrom(t *testing.T) {
	t.Parallel()

	small, big := payload(100, 3), payload(10_000, 4)
	closed := 0
	from := func(b []byte) func() (io.Reader, error) {
		return func() (io.Reader, error) { return closeCounter{bytes.NewReader(b), &closed}, nil }
	}

	streamed, held := NewRoot(), NewRoot()
	for _, s := range []*Storage{streamed, held} {
		sub, err := s.AddStorage("Sub")
		if err != nil {
			t.Fatal(err)
		}
		if s == streamed {
			err = errors.Join(s.AddStreamFrom("Small", int64(len(small)), from(small)),
				sub.AddStreamFrom("Big", int64(len(big)), from(big)), s.AddStreamFrom("Empty", 0, from(nil)))
		} else {
			err = errors.Join(s.AddStream("Small", small), sub.AddStream("Big", big), s.AddStream("Empty", nil))
		}
		if err != nil {
			t.Fatal(err)
		}
	}

	// A stream read from a source is written as one given whole.
	var a, b bytes.Buffer
	if _, err := streamed.WriteTo(&a); err != nil {
		t.Fatal(err)
	}
	if _, err := held.WriteTo(&b); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatal("a streamed file differs from the same file written from memory")
	}
	if closed != 2 { // the source of the empty stream is not opened
		t.Fatalf("%d sources closed, want 2", closed)
	}

	r := writeAndOpen(t, streamed)
	if got, err := r.Root.Lookup("Sub/Big").Bytes(); err != nil || !bytes.Equal(got, big) {
		t.Fatalf("Big: %d bytes, %v", len(got), err)
	}
	if got, err := r.Root.Find("Small").Bytes(); err != nil || !bytes.Equal(got, small) {
		t.Fatalf("Small: %d bytes, %v", len(got), err)
	}

	// Extra bytes are ignored; missing ones fail the write.
	extra := NewRoot()
	if err := extra.AddStreamFrom("S", 10, from(big)); err != nil {
		t.Fatal(err)
	}
	if got, err := writeAndOpen(t, extra).Root.Find("S").Bytes(); err != nil || !bytes.Equal(got, big[:10]) {
		t.Fatalf("first bytes of a longer source: %x, %v", got, err)
	}
	short := NewRoot()
	if err := short.AddStreamFrom("S", 5000, from(small)); err != nil {
		t.Fatal(err)
	}
	if _, err := short.WriteTo(io.Discard); err == nil || !strings.Contains(err.Error(), "100 of its 5000 bytes") {
		t.Fatalf("short source: %v", err)
	}
	failing := NewRoot()
	if err := failing.AddStreamFrom("S", 1, func() (io.Reader, error) { return nil, io.ErrClosedPipe }); err != nil {
		t.Fatal(err)
	}
	if _, err := failing.WriteTo(io.Discard); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("failing source: %v", err)
	}

	for _, size := range []int64{-1, maxStreamSize + 1} {
		if err := NewRoot().AddStreamFrom("S", size, from(nil)); err == nil {
			t.Errorf("size %d accepted", size)
		}
	}
	if err := NewRoot().AddStreamFrom("S", 1, nil); err == nil {
		t.Error("a stream without source accepted")
	}
}
