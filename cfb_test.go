package cfb

import "testing"

func TestEntryKindString(t *testing.T) {
	cases := []struct {
		kind EntryKind
		want string
	}{
		{KindStorage, "storage"},
		{KindStream, "stream"},
		{KindRoot, "root"},
		{KindUnknown, "unknown"},
		{EntryKind(99), "unknown"}, // any undeclared value falls back to "unknown"
	}
	for _, c := range cases {
		if got := c.kind.String(); got != c.want {
			t.Errorf("EntryKind(%d).String() = %q, want %q", c.kind, got, c.want)
		}
	}
}

func TestParseCLSIDRoundTrip(t *testing.T) {
	const want = "00020D0B-0000-0000-C000-000000000046"
	c, err := ParseCLSID(want)
	if err != nil {
		t.Fatalf("ParseCLSID: %v", err)
	}
	if got := c.String(); got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}

	// Braces and lowercase hex digits are accepted too.
	c2, err := ParseCLSID("{00020d0b-0000-0000-c000-000000000046}")
	if err != nil {
		t.Fatalf("ParseCLSID with braces: %v", err)
	}
	if c2 != c {
		t.Fatalf("braced/lowercase form parsed to a different CLSID")
	}
}

func TestParseCLSIDInvalid(t *testing.T) {
	cases := []string{
		"",
		"00020D0B-0000-0000-C000", // too few groups
		"00020D0B-0000-0000-C000-000000000046-extra",
		"0020D0B-0000-0000-C000-000000000046",  // first group too short
		"00020D0B-000-0000-C000-000000000046",  // second group too short
		"00020D0B-0000-000-C000-000000000046",  // third group too short
		"00020D0B-0000-0000-C00-000000000046",  // fourth group too short
		"00020D0B-0000-0000-C000-00000000046",  // fifth group too short
		"ZZ020D0B-0000-0000-C000-000000000046", // not valid hex
	}
	for _, s := range cases {
		if _, err := ParseCLSID(s); err == nil {
			t.Errorf("ParseCLSID(%q): expected an error, got nil", s)
		}
	}
}

func TestMustParseCLSIDPanicsOnInvalid(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("MustParseCLSID did not panic on an invalid CLSID")
		}
	}()
	MustParseCLSID("not-a-clsid")
}

func TestCLSIDIsZero(t *testing.T) {
	var zero CLSID
	if !zero.IsZero() {
		t.Fatal("zero-value CLSID should report IsZero() == true")
	}
	nonZero := MustParseCLSID("00020D0B-0000-0000-C000-000000000046")
	if nonZero.IsZero() {
		t.Fatal("non-zero CLSID should report IsZero() == false")
	}
}

func TestCompareNames(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"same", "same", 0},
		{"Same", "same", 0}, // case-insensitive
		{"a", "ab", -1},     // shorter sorts first when it's a prefix
		{"ab", "a", 1},      // longer sorts after
		{"abc", "abd", -1},  // differs in the final unit
		{"abd", "abc", 1},
		{"Apple", "banana", -1}, // case-insensitive ordering, not ASCII order
	}
	for _, c := range cases {
		if got := compareNames(c.a, c.b); sign(got) != c.want {
			t.Errorf("compareNames(%q, %q) = %d, want sign %d", c.a, c.b, got, c.want)
		}
	}
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}

func TestUpperCodeUnitPassesThroughSurrogates(t *testing.T) {
	// Surrogate code units (used to encode runes outside the BMP) are not
	// valid standalone characters, so upperCodeUnit must leave them as-is
	// rather than attempt to case-fold them.
	for u := uint16(0xD800); u <= 0xDFFF; u += 0x100 {
		if got := upperCodeUnit(u); got != u {
			t.Errorf("upperCodeUnit(%#04x) = %#04x, want unchanged", u, got)
		}
	}
	if got := upperCodeUnit('a'); got != 'A' {
		t.Errorf("upperCodeUnit('a') = %q, want 'A'", got)
	}
}

func TestDivRoundUp(t *testing.T) {
	cases := []struct{ n, unit, want int }{
		{0, 512, 0},
		{1, 512, 1},
		{512, 512, 1},
		{513, 512, 2},
		{1024, 512, 2},
	}
	for _, c := range cases {
		if got := divRoundUp(c.n, c.unit); got != c.want {
			t.Errorf("divRoundUp(%d, %d) = %d, want %d", c.n, c.unit, got, c.want)
		}
	}
}
