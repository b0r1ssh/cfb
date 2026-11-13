# cfb

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
- **Writer**: in-memory tree builder (`Storage`/`AddStorage`/`AddStream`)
  that writes version 3 (512-byte sector) files, which is what Outlook and
  Excel themselves produce. Reading accepts versions 3 and 4.

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

book := r.Root.Find("Workbook")
data, err := book.Bytes()
```

Writing:

```go
root := cfb.NewRoot()
root.SetCLSID(cfb.MustParseCLSID("00020D0B-0000-0000-C000-000000000046"))
sub, _ := root.AddStorage("__recip_version1.0_#00000000")
_ = sub.AddStream("__substg1.0_3001001F", data)
_, err := root.WriteTo(w)
```
