// Package apdu implements parsing and conversion of Application Protocol Data Units (APDU) which is the communication format between a card and off-card applications. The format of the APDU is defined in ISO specification 7816-4.
// The package has support for extended length APDUs as well.
package apdu

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	// OffsetCla defines the offset to the Cla byte of a CAPDU
	OffsetCla int = 0
	// OffsetIns defines the offset to the Ins byte of a CAPDU
	OffsetIns int = 1
	// OffsetP1 defines the offset to the P1 byte of a CAPDU
	OffsetP1 int = 2
	// OffsetP2 defines the offset to the P2 byte of a CAPDU
	OffsetP2 int = 3
	// OffsetLcStandard defines the offset to the LC byte of a standard length CAPDU
	OffsetLcStandard int = 4
	// OffsetLcExtended defines the offset to the LC byte of an extended length CAPDU
	OffsetLcExtended int = 5
	// OffsetCdataStandard defines the offset to the beginning of the data field of a standard length CAPDU
	OffsetCdataStandard int = 5
	// OffsetCdataExtended defines the offset to the beginning of the data field of an extended length CAPDU
	OffsetCdataExtended int = 7
	// MaxLenCommandDataStandard defines the maximum command data length of a standard length CAPDU
	MaxLenCommandDataStandard int = 255
	// MaxLenResponseDataStandard defines the maximum response data length of a standard length RAPDU
	MaxLenResponseDataStandard int = 256
	// MaxLenCommandDataExtended defines the maximum command data length of an extended length CAPDU
	MaxLenCommandDataExtended int = 65535
	// MaxLenResponseDataExtended defines the maximum response data length of an extended length RAPDU
	MaxLenResponseDataExtended int = 65536
	// LenHeader defines the length of the header of an APDU
	LenHeader int = 4
	// LenLCStandard defines the length of the LC of a standard length APDU
	LenLCStandard int = 1
	// LenLCExtended defines the length of the LC of an extended length APDU
	LenLCExtended int = 3
	// LenResponseTrailer defines the length of the trailer of a Response APDU
	LenResponseTrailer int    = 2
	packageTag         string = "skythen/apdu"
)

// Capdu represents a Command APDU
type Capdu struct {
	Cla  byte   // Cla represents the class byte
	Ins  byte   // Ins represents the class byte
	P1   byte   // P1 represents the class byte
	P2   byte   // P2 represents the class byte
	Data []byte // Data represents the data field
	Ne   int    // Ne represents the total number of expexted response data byte (not LE encoded)
}

// Rapdu represents a Response APDU
type Rapdu struct {
	Data []byte // Data represents the data field
	SW1  byte   // SW1 represents the first byte of a status word
	SW2  byte   // SW2 represents the second byte of a status word
}

// ParseCapdu parses the byte representation of a Command APDU and returns a Capdu.
// The minimum length of a CAPDU is 4 byte (Case 1) and the maximum length is 65544 (Extended Length Case 4)
// While parsing it is checked if the Lc, if present, indicates the correct data length.
// Any errors that occur while parsing are returned.
func ParseCapdu(c []byte) (Capdu, error) {
	if len(c) < LenHeader || len(c) > 65544 {
		return Capdu{}, fmt.Errorf("%s: failed to parse Capdu because of invalid length - a CAPDU must consist of at least 4 byte and maximum of 65544 byte, got %d", packageTag, len(c))
	}

	// CASE 1 command: only HEADER
	if len(c) == LenHeader {
		return Capdu{Cla: c[OffsetCla], Ins: c[OffsetIns], P1: c[OffsetP1], P2: c[OffsetP2], Data: nil, Ne: 0}, nil
	}

	// check for zero byte
	if c[OffsetLcStandard] == 0x00 {
		// check for extended length CAPDU
		if len(c[OffsetLcExtended:]) > 0 {
			return parseCapduExtendedLength(c)
		}
	}

	return parseCapduStandardLength(c)
}

func parseCapduStandardLength(c []byte) (Capdu, error) {
	// STANDARD CASE 2 command: HEADER | LE
	if len(c) == LenHeader+LenLCStandard {
		le := int(c[OffsetLcStandard]) // in this case, no LC is present
		if le == 0 {
			return Capdu{Cla: c[OffsetCla], Ins: c[OffsetIns], P1: c[OffsetP1], P2: c[OffsetP2], Data: nil, Ne: MaxLenResponseDataStandard}, nil
		}

		return Capdu{Cla: c[OffsetCla], Ins: c[OffsetIns], P1: c[OffsetP1], P2: c[OffsetP2], Data: nil, Ne: le}, nil
	}

	bodyLen := len(c) - LenHeader

	// check if lc indicates length which is not out of bounds
	lc := int(c[OffsetLcStandard])
	if lc != bodyLen-LenLCStandard && lc != bodyLen-LenLCStandard-1 {
		return Capdu{}, fmt.Errorf("%s: failed to parse Capdu because of invalid LC value - LC indicates length %d but body length after LC is %d", packageTag, lc, bodyLen-LenLCStandard)
	}

	data := c[OffsetCdataStandard : OffsetCdataStandard+lc]

	// STANDARD CASE 3 command: HEADER | LC | DATA
	if len(c) == LenHeader+LenLCStandard+len(data) {
		return Capdu{Cla: c[OffsetCla], Ins: c[OffsetIns], P1: c[OffsetP1], P2: c[OffsetP2], Data: data, Ne: 0}, nil
	}

	// STANDARD CASE 4 command: HEADER | LC | DATA | LE
	var ne int

	le := int(c[len(c)-1]) // get last byte
	if le == 0 {
		ne = MaxLenResponseDataStandard
	} else {
		ne = le
	}

	return Capdu{Cla: c[OffsetCla], Ins: c[OffsetIns], P1: c[OffsetP1], P2: c[OffsetP2], Data: data, Ne: ne}, nil
}

func parseCapduExtendedLength(c []byte) (Capdu, error) {
	// EXTENDED CASE 2 command: HEADER | LE
	if len(c) == LenHeader+LenLCExtended { // in this case no LC is present, but the two byte LE with leading zero byte
		var ne int

		le := int(binary.BigEndian.Uint16(c[OffsetLcExtended:]))

		if le == 0x00 {
			ne = MaxLenResponseDataExtended
		} else {
			ne = le
		}

		return Capdu{Cla: c[OffsetCla], Ins: c[OffsetIns], P1: c[OffsetP1], P2: c[OffsetP2], Data: nil, Ne: ne}, nil
	}

	bodyLen := len(c) - LenHeader

	lc := int(binary.BigEndian.Uint16(c[OffsetLcExtended : OffsetLcExtended+2]))
	if lc != bodyLen-LenLCExtended && lc != bodyLen-LenLCExtended-2 {
		return Capdu{}, fmt.Errorf("%s: failed to parse Capdu because of invalid LC value - LC indicates data length %d but body length after LC is %d", packageTag, lc, bodyLen-LenLCExtended)
	}

	data := c[OffsetCdataExtended : OffsetCdataExtended+lc]

	// EXTENDED CASE 3 command: HEADER | LC | DATA
	if len(c) == LenHeader+LenLCExtended+len(data) {
		return Capdu{Cla: c[OffsetCla], Ins: c[OffsetIns], P1: c[OffsetP1], P2: c[OffsetP2], Data: data, Ne: 0}, nil
	}

	// EXTENDED CASE 4 command: HEADER | LC | DATA | LE
	var ne int

	le := int(binary.BigEndian.Uint16(c[len(c)-2:])) // get last two bytes

	if le == 0x00 {
		ne = MaxLenResponseDataExtended
	} else {
		ne = le
	}

	return Capdu{Cla: c[OffsetCla], Ins: c[OffsetIns], P1: c[OffsetP1], P2: c[OffsetP2], Data: data, Ne: ne}, nil
}

// ParseCapduFromString decodes the hex-string representation of a Command APDU, calls ParseCapdu and returns a Capdu.
// Any errors that occur while decoding and parsing are returned.
func ParseCapduFromString(s string) (Capdu, error) {
	if len(s)%2 != 0 {
		return Capdu{}, fmt.Errorf("%s: failed to parse Capdu because of uneven number of hex characters", packageTag)
	}

	if len(s) < 8 || len(s) > 131088 {
		return Capdu{}, fmt.Errorf("%s: failed to parse Capdu because of invalid length of hex string - a CAPDU must consist of at least 4 byte and maximum of 65544 byte, got %d", packageTag, len(s)/2)
	}

	tmp, err := hex.DecodeString(s)
	if err != nil {
		return Capdu{}, fmt.Errorf("%s: failed to parse Capdu because of hex conversion error - %s", packageTag, err.Error())
	}

	return ParseCapdu(tmp)
}

// ParseRapdu parses the byte representation of a Response APDU and returns a Rapdu.
// The minimum length of a RAPDU is 2 byte and the maximum length is 65544
// Any errors that occur while parsing are returned.
func ParseRapdu(b []byte) (Rapdu, error) {
	var (
		data []byte
		sw1  byte
		sw2  byte
	)

	if len(b) < LenResponseTrailer || len(b) > 65538 {
		return Rapdu{}, fmt.Errorf("%s: failed to parse Rapdu because of invalid length - a RAPDU must consist of at least 2 byte and maximum of 65538 byte, got %d", packageTag, len(b))
	}

	if len(b) == LenResponseTrailer {
		sw1 = b[0]
		sw2 = b[1]
	}

	if len(b) > LenResponseTrailer {
		data = b[:len(b)-LenResponseTrailer]
		sw1 = b[len(b)-2]
		sw2 = b[len(b)-1]
	}

	return Rapdu{Data: data, SW1: sw1, SW2: sw2}, nil
}

// ParseRapduFromString decodes the hex-string representation of a Response APDU, calls ParseRapdu and returns a Rapdu.
// Any errors that occur while decoding and parsing are returned.
func ParseRapduFromString(s string) (Rapdu, error) {
	if len(s)%2 != 0 {
		return Rapdu{}, fmt.Errorf("%s: failed to parse Rapdu because of uneven number of hex characters", packageTag)
	}

	if len(s) < 4 || len(s) > 131076 {
		return Rapdu{}, fmt.Errorf("%s: failed to parse Rapdu because of invalid length of hex string - a RAPDU must consist of at least 2 byte and maximum of 65538 byte, got %d", packageTag, len(s)/2)
	}

	tmp, err := hex.DecodeString(s)
	if err != nil {
		return Rapdu{}, fmt.Errorf("%s: failed to parse Rapdu because of hex conversion error - %s", packageTag, err.Error())
	}

	return ParseRapdu(tmp)
}

// Bytes returns the byte representation of the CAPDU.
// Case and format (standard/extended) of the CAPDU are inferred and applied automatically.
// The upper limit for the length of Capdu.Data is 65535 and 65536 for Capdu.Ne - values that exceed these limits are truncated and set to the upper limit.
// This is to avoid returning errors and to make working with APDUs more convenient.
func (c Capdu) Bytes() []byte {
	var (
		capdu   []byte
		dataLen int
		ne      int
	)

	header := []byte{c.Cla, c.Ins, c.P1, c.P2}
	copy(capdu, header)

	ca := c.determineCase()

	// CASE 1: HEADER
	if ca == 1 {
		return []byte{c.Cla, c.Ins, c.P1, c.P2}
	} else if ca == 2 {
		// CASE 2: HEADER | LE
		if c.Ne > MaxLenResponseDataStandard {
			// extended length format

			if c.Ne > MaxLenResponseDataExtended {
				ne = MaxLenResponseDataExtended
			} else {
				ne = c.Ne
			}

			le := make([]byte, LenLCExtended) // first byte is zero byte, so LE length is equal to LC length

			if ne == MaxLenResponseDataExtended {
				le[1] = 0x00
				le[2] = 0x00
			} else {
				le[1] = (byte)((c.Ne >> 8) & 0xFF)
				le[2] = (byte)(c.Ne & 0xFF)
			}

			capdu = make([]byte, LenHeader+LenLCExtended)
			copy(capdu, header)
			copy(capdu[LenHeader:], le)

			return capdu
		}
		//standard format
		capdu = make([]byte, LenHeader+LenLCStandard+len(c.Data))
		copy(capdu, header)

		if c.Ne == MaxLenResponseDataStandard {
			capdu[LenHeader] = 0x00

			return capdu
		}

		capdu = make([]byte, LenHeader+LenLCStandard+len(c.Data))
		capdu[OffsetCla] = c.Cla
		capdu[OffsetIns] = c.Ins
		capdu[OffsetP1] = c.P1
		capdu[OffsetP2] = c.P2
		capdu[LenHeader] = byte(c.Ne)

		return capdu
	} else if ca == 3 {
		// CASE 3: HEADER | LC | DATA
		if len(c.Data) > MaxLenCommandDataStandard {
			// truncate data if it exceeds max length
			if len(c.Data) > MaxLenCommandDataExtended {
				capdu = make([]byte, LenHeader+LenLCExtended+MaxLenCommandDataExtended)
				dataLen = MaxLenCommandDataExtended
			} else {
				capdu = make([]byte, LenHeader+LenLCExtended+len(c.Data))
				dataLen = len(c.Data)
			}
			// extended length format
			lc := make([]byte, LenLCExtended)
			lc[1] = (byte)((dataLen >> 8) & 0xFF)
			lc[2] = (byte)(dataLen & 0xFF)

			copy(capdu, header)
			copy(capdu[LenHeader:], lc)
			copy(capdu[LenHeader+LenLCExtended:], c.Data)

			return capdu
		}

		dataLen = len(c.Data)
		//standard format
		capdu = make([]byte, LenHeader+LenLCStandard+dataLen)
		copy(capdu, header)
		capdu[OffsetLcStandard] = byte(dataLen)
		copy(capdu[LenHeader+LenLCStandard:], c.Data)

		return capdu
	}

	// CASE 4: HEADER | LC | DATA | LE
	if c.Ne > MaxLenResponseDataStandard || len(c.Data) > MaxLenCommandDataStandard {
		// extended length format
		// truncate data if it exceeds max length
		if len(c.Data) > MaxLenCommandDataExtended {
			capdu = make([]byte, LenHeader+LenLCExtended+MaxLenCommandDataExtended+2)

			dataLen = MaxLenCommandDataExtended
		} else {
			capdu = make([]byte, LenHeader+LenLCExtended+len(c.Data)+2)

			dataLen = len(c.Data)
		}

		// truncate ne if it exceeds max length
		if c.Ne > MaxLenResponseDataExtended {
			ne = MaxLenResponseDataExtended
		} else {
			ne = c.Ne
		}

		le := make([]byte, 2)

		if ne == MaxLenResponseDataExtended {
			le[0] = 0x00
			le[1] = 0x00
		} else {
			le[0] = (byte)((c.Ne >> 8) & 0xFF)
			le[1] = (byte)(c.Ne & 0xFF)
		}

		lc := make([]byte, LenLCExtended) // first byte is zero byte
		lc[1] = (byte)((dataLen >> 8) & 0xFF)
		lc[2] = (byte)(dataLen & 0xFF)

		copy(capdu, header)
		copy(capdu[LenHeader:], lc)
		copy(capdu[LenHeader+LenLCExtended:], c.Data)
		copy(capdu[LenHeader+LenLCExtended+dataLen:], le)

		return capdu
	}

	dataLen = len(c.Data)
	//standard format
	capdu = make([]byte, LenHeader+LenLCStandard+dataLen+1)
	copy(capdu, header)
	capdu[OffsetLcStandard] = byte(dataLen)
	copy(capdu[OffsetCdataStandard:], c.Data)
	capdu[OffsetCdataStandard+dataLen] = byte(c.Ne)

	return capdu
}

func (c Capdu) determineCase() int {
	if len(c.Data) == 0 && c.Ne == 0 {
		return 1
	}

	if len(c.Data) == 0 && c.Ne > 0 {
		return 2
	}

	if len(c.Data) != 0 && c.Ne == 0 {
		return 3
	}

	return 4
}

// IsExtendedLength returns true if the CAPDU is of extended length (len of Data > 65535 or Ne > 65536), else false
func (c Capdu) IsExtendedLength() bool {
	return c.Ne > MaxLenResponseDataStandard || len(c.Data) > MaxLenCommandDataStandard
}

// Lc returns the byte representation of the CAPDU's Lc if present, otherwise nil.
func (c Capdu) Lc() []byte {
	var lc []byte

	if len(c.Data) == 0 {
		return nil
	}

	if len(c.Data) > MaxLenCommandDataStandard {
		lc = make([]byte, LenLCExtended) // first byte is zero byte
		lc[1] = (byte)((len(c.Data) >> 8) & 0xFF)
		lc[2] = (byte)(len(c.Data) & 0xFF)
	} else {
		lc = make([]byte, LenLCStandard)
		lc[0] = byte(len(c.Data))
	}

	return lc
}

// String calls Bytes and returns the hex encoded string representation of the CAPDU.
func (c Capdu) String() string {
	return strings.ToUpper(hex.EncodeToString(c.Bytes()))
}

// Bytes returns the byte representation of the RAPDU.
// Case and format (standard/extended) of the CAPDU are inferred and applied automatically.
// The upper limit for the length of Capdu.Data is 65535 and 65536 for Capdu.Ne - values that exceed these limits are truncated and set to the upper limit.
// This is to avoid returning errors and to make working with APDUs more convenient.
func (r Rapdu) Bytes() []byte {
	var rapdu []byte

	// truncate data if it exceeds max length
	if len(r.Data) > MaxLenResponseDataExtended {
		rapdu = make([]byte, MaxLenResponseDataExtended+LenResponseTrailer)
	} else {
		rapdu = make([]byte, len(r.Data)+LenResponseTrailer)
	}

	copy(rapdu, r.Data)
	rapdu[len(rapdu)-2] = r.SW1
	rapdu[len(rapdu)-1] = r.SW2

	return rapdu
}

// IsSuccess returns true if the RAPDU indicates the successful execution of a command ('0x9000'), otherwise false.
func (r Rapdu) IsSuccess() bool {
	return r.SW1 == 0x90 && r.SW2 == 0x00
}

// String calls Bytes and returns the hex encoded string representation of the RAPDU.
func (r Rapdu) String() string {
	return strings.ToUpper(hex.EncodeToString(r.Bytes()))
}
