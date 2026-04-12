# APDU

[![CI](https://github.com/skythen/apdu/actions/workflows/ci.yml/badge.svg)](https://github.com/skythen/apdu/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/skythen/apdu/branch/master/graph/badge.svg)](https://codecov.io/gh/skythen/apdu)
[![GoDoc](https://godoc.org/github.com/skythen/apdu?status.svg)](http://godoc.org/github.com/skythen/apdu)
[![Go Report Card](https://goreportcard.com/badge/github.com/skythen/apdu)](https://goreportcard.com/report/github.com/skythen/apdu)

Package apdu implements encoding and decoding of Application Protocol Data Units (APDU) as defined in [ISO 7816-4](https://www.iso.org/obp/ui/#iso:std:iso-iec:7816:-4:en). Both standard and extended length APDUs are supported.

## Install

```
go get github.com/skythen/apdu
```

## Command APDU (Capdu)

### Parse from bytes or hex string

```go
c, err := apdu.ParseCapdu([]byte{0x80, 0xF2, 0xE0, 0x02, 0x02, 0x4F, 0x00, 0x00})

c, err := apdu.ParseCapduHexString("80F2E002024F0000")
```

### Create from struct

Ne is the expected number of response bytes (not the encoded LE value).

```go
c := apdu.Capdu{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x00, Data: []byte{0xA0, 0x00, 0x00, 0x00, 0x03}, Ne: 256}
```

### Convert to bytes or hex string

The APDU case and format (standard/extended) are determined automatically.

```go
b, err := c.Bytes()
s, err := c.String()
```

### Check extended length

```go
if c.IsExtendedLength() {
    // len(Data) > 255 or Ne > 256
}
```

## Response APDU (Rapdu)

### Parse from bytes or hex string

```go
r, err := apdu.ParseRapdu([]byte{0x01, 0x02, 0x03, 0x90, 0x00})

r, err := apdu.ParseRapduHexString("0102039000")
```

### Create from struct

```go
r := apdu.Rapdu{Data: []byte{0x01, 0x02, 0x03}, SW1: 0x90, SW2: 0x00}
```

### Convert to bytes or hex string

```go
b, err := r.Bytes()
s, err := r.String()
```

### Check response status

```go
r.IsSuccess() // SW1=0x61xx or SW1SW2=0x9000
r.IsWarning() // SW1=0x62xx or SW1=0x63xx
r.IsError()   // SW1=0x64xx, 0x65xx, or 0x67xx-0x6Fxx
```