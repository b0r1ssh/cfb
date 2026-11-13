package cfb

import (
	"bytes"
	"math/rand"
	"testing"
)

// payload returns n deterministic pseudo-random bytes, so tests can compare
// round-tripped content without storing large literal fixtures.
func payload(n int, seed int64) []byte {
	b := make([]byte, n)
	rand.New(rand.NewSource(seed)).Read(b)
	return b
}

// writeAndOpen serializes root with WriteTo and re-opens the result with
// Open, checking the invariants every writer output must satisfy along the
// way. It is the shared entry point used by both the writer and reader
// round-trip tests.
func writeAndOpen(t *testing.T, root *Storage) *Reader {
	t.Helper()
	var buf bytes.Buffer
	n, err := root.WriteTo(&buf)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if n != int64(buf.Len()) {
		t.Fatalf("WriteTo returned %d, wrote %d bytes", n, buf.Len())
	}
	if buf.Len()%sectorSize512 != 0 {
		t.Fatalf("file size %d is not a multiple of the sector size", buf.Len())
	}
	r, err := Open(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return r
}
