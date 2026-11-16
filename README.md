# cfb

[![CI](https://github.com/b0r1ssh/cfb/actions/workflows/go-test.yml/badge.svg)](https://github.com/b0r1ssh/cfb/actions/workflows/go-test.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/b0r1ssh/cfb.svg)](https://pkg.go.dev/github.com/b0r1ssh/cfb)
[![codecov](https://codecov.io/gh/b0r1ssh/cfb/graph/badge.svg?token=F3K90H8KRN)](https://codecov.io/gh/b0r1ssh/cfb)

Pure Go reader and writer for the Compound File Binary File Format
([MS-CFB]), the structured-storage container used by legacy Microsoft
file formats: Outlook `.msg`/`.oft`/`.doc`/`.xls`/`.ppt`/`.msi`, and others.

This package has no knowledge of what any particular format stores inside
the container it only deals with the storage/stream tree, FAT and mini
FAT, same as `encoding/zip` does not know what's inside the files it
contains.

## Features

- **Reader**: builds the full directory tree (storages and streams,
  recursively) from the header, FAT and mini FAT. Stream content is read
  lazily: `Entry.Open` returns a `*Stream` implementing `io.Reader`,
  `io.ReaderAt` and `io.Seeker`, resolving sectors on demand instead of
  loading the whole stream up front — `Entry.Bytes` is a convenience
  wrapper around `io.ReadAll` for callers that just want everything.
  Entries expose their CLSID, state bits and timestamps, and can be
  navigated with `Entry.Lookup` (slash-separated paths) and `Entry.Walk`.
  Failures wrap `ErrNotCompoundFile`, `ErrUnsupported` or `ErrCorrupt`, so
  callers can tell them apart with `errors.Is`.
- **Writer**: in-memory tree builder (`Storage`/`AddStorage`/`AddStream`)
  that writes version 3 (512-byte sector) files, which is what Outlook and
  Excel themselves produce. Reading accepts versions 3 and 4. Storages can
  carry a CLSID, state bits and timestamps; streams are limited to 2 GiB,
  the version 3 maximum. `AddStreamFrom` adds a stream whose content is
  read from an `io.Reader` while the file is written, so that large streams
  are not held in memory.

## Install

```sh
go get github.com/b0r1ssh/cfb
```

## Usage

Reading:

```go
f, _ := os.Open("workbook.xls")
defer f.Close()
st, _ := f.Stat()
r, err := cfb.Open(f, st.Size())
if errors.Is(err, cfb.ErrNotCompoundFile) {
	// not a CFB container at all
}

book := r.Root.Lookup("Workbook")
data, err := book.Bytes()

_ = r.Root.Walk(func(path string, e *cfb.Entry) error {
	fmt.Println(path, e.Kind, e.Size)
	return nil
})
```

Writing:

```go
root := cfb.NewRoot()
root.SetCLSID(cfb.MustParseCLSID("00020D0B-0000-0000-C000-000000000046"))
sub, _ := root.AddStorage("__recip_version1.0_#00000000")
sub.SetTimes(time.Now(), time.Now())
_ = sub.AddStream("__substg1.0_3001001F", data)
_, err := root.WriteTo(w)
```

## Release workflow for contributors

Merging a pull request into `main` automatically creates a Git tag and a
GitHub release. Before merging, use at most one of these labels to select the
semantic version increment:

- `patch`: bug fixes and other backward-compatible changes (`v1.2.3` to
	`v1.2.4`).
- `minor`: new backward-compatible functionality (`v1.2.3` to `v1.3.0`).
- `major`: breaking API changes (`v1.2.3` to `v2.0.0`).

When no release label is present, the workflow uses `patch`. Do not combine
`patch`, `minor`, and `major` labels on one pull request; the release workflow
will fail if more than one is present.

Use the `skip-release` label for documentation, CI, or other changes that do
not need a new module version. When a pull request with this label is merged,
the publish workflow skips the release entirely.
