# APDU

[![Build Status](https://travis-ci.org/skythen/apdu.svg?branch=master)](https://travis-ci.org/skythen/apdu)
[![Coverage Status](https://coveralls.io/repos/github/skythen/apdu/badge.svg)](https://coveralls.io/github/skythen/apdu)
[![GoDoc](https://godoc.org/github.com/skythen/apdu?status.svg)](http://godoc.org/github.com/skythen/apdu)
[![Go Report Card](https://goreportcard.com/badge/github.com/skythen/apdu)](https://goreportcard.com/report/github.com/skythen/apdu)

Package apdu implements parsing and conversion of Application Protocol Data Units (APDU) which is the communication
format between a card and off-card applications. The format of the APDU is defined
in [ISO specification 7816-4](https://www.iso.org/obp/ui/#iso:std:iso-iec:7816:-4:en).

The package has support for extended length APDUs as well.

`go get github.com/skythen/apdu`

## Capdu

### Create

You can create a Capdu either by creating a Capdu struct:

```go
  capduCase1 := Capdu{Cla: 0x00, Ins: 0xAB, P1: 0xCD, P2: 0xEF}
  capduCase2 := Capdu{Cla: 0x80, Ins: 0xCA, P1: 0x00, P2: 0x66, Ne: 256}
  capduCase3 := Capdu{Cla: 0x80, Ins: 0xF2, P1: 0xE0, P2: 0x02, Data: []byte{0x4F, 0x00}, Ne: 256}
  capduCase4 := Capdu{Cla: 0x00, Ins: 0xAA, P1: 0xBB, P2: 0xCC, Data: make([]byte, 65535), Ne: 65536}
```

(please note that Ne is the expected length of response in bytes, not encoded as Le)

or by parsing from bytes/strings:

```go
  bCapdu, err := apdu.ParseCapdu([]byte{0x80, 0xF2, 0xE0, 0x02, 0x02, 0x4F, 0x00, 0x00)
  sCapdu, err := apdu.ParseCapduHexString("80F2E002024F0000")
```

### Convert

#### Bytes

You can convert a Capdu to its bytes representation with the Bytes() function. Case and format (standard/extended) are
inferred and applied automatically.

```go
  b, err := capdu.Bytes()
```

#### String

You can convert a Capdu to its hex representation as well. The same rules apply as for conversion to bytes:

```go
  s, err := capdu.String()
```

### Utility

#### IsExtendedLength

Use IsExtendedLength to check if the CAPDU is of extended length (len of Data > 65535 or Ne > 65536):

```go
  ext := capdu.IsExtendedLength()
```

## Rapdu

### Create

You can create a Rapdu either by creating a Rapdu struct:

```go
  r1 := Rapdu{SW1: 0x90, SW2: 0x00}
  r2 := Rapdu{Data: []byte{0x01, 0x02, 0x03}, SW1: 0x90, SW2: 0x00}
```

or by parsing from bytes/strings:

```go
  r1, err := apdu.ParseRapdu([]byte{0x90, 0x00)
  r2, err := apdu.ParseRapduHexString("0102039000")
```

### Convert

#### Bytes

You can convert a Rapdu to its bytes representation with the Bytes() function.

```go
  b, err := rapdu.Bytes()
```

#### String

You can convert a Rapdu to its hex representation as well.

```go
  s, err := rapdu.String()
```

### Utility

#### Success/Warning/Error

Use IsSuccess/IsWarning/IsError to check the response status.

```go
  if !rapdu.IsSuccess() {
	  ...
  }

  if rapdu.IsWarning() || rapdu.IsError(){
      ...
  }
```