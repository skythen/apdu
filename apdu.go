// Package apdu implements parsing and conversion of Application Protocol Data Units (APDU) which is the communication format between a card and off-card applications. The format of the APDU is defined in ISO specification 7816-4.
// The package has support for extended length APDUs as well.
package apdu

import (
	"encoding/binary"
	"encoding/hex"
	"strings"

	"github.com/pkg/errors"
)

const (
	// OffsetCla defines the offset to the Cla byte of a Capdu.
	OffsetCla int = 0
	// OffsetIns defines the offset to the Ins byte of a Capdu.
	OffsetIns int = 1
	// OffsetP1 defines the offset to the P1 byte of a Capdu.
	OffsetP1 int = 2
	// OffsetP2 defines the offset to the P2 byte of a Capdu.
	OffsetP2 int = 3
	// OffsetLcStandard defines the offset to the LC byte of a standard length Capdu.
	OffsetLcStandard int = 4
	// OffsetLcExtended defines the offset to the LC byte of an extended length Capdu.
	OffsetLcExtended int = 5
	// OffsetCdataStandard defines the offset to the beginning of the data field of a standard length Capdu.
	OffsetCdataStandard int = 5
	// OffsetCdataExtended defines the offset to the beginning of the data field of an extended length Capdu.
	OffsetCdataExtended int = 7
	// MaxLenCommandDataStandard defines the maximum command data length of a standard length Capdu.
	MaxLenCommandDataStandard int = 255
	// MaxLenResponseDataStandard defines the maximum response data length of a standard length RAPDU.
	MaxLenResponseDataStandard int = 256
	// MaxLenCommandDataExtended defines the maximum command data length of an extended length Capdu.
	MaxLenCommandDataExtended int = 65535
	// MaxLenResponseDataExtended defines the maximum response data length of an extended length RAPDU.
	MaxLenResponseDataExtended int = 65536
	// LenHeader defines the length of the header of an APDU.
	LenHeader int = 4
	// LenLCStandard defines the length of the LC of a standard length APDU.
	LenLCStandard int = 1
	// LenLCExtended defines the length of the LC of an extended length APDU.
	LenLCExtended int = 3
	// LenResponseTrailer defines the length of the trailer of a Response APDU.
	LenResponseTrailer int    = 2
	packageTag         string = "skythen/apdu"
)

// Capdu is a Command APDU.
type Capdu struct {
	Cla  byte   // Cla is the class byte.
	Ins  byte   // Ins is the instruction byte.
	P1   byte   // P1 is the p1 byte.
	P2   byte   // P2 is the p2 byte.
	Data []byte // Data is the data field.
	Ne   int    // Ne is the total number of expected response data byte (not LE encoded).
}

// ParseCapdu parses a Command APDU and returns a Capdu.
func ParseCapdu(c []byte) (*Capdu, error) {
	if len(c) < LenHeader || len(c) > 65544 {
		return nil, errors.Errorf("%s: invalid length - Capdu must consist of at least 4 byte and maximum of 65544 byte, got %d", packageTag, len(c))
	}

	// CASE 1 command: only HEADER
	if len(c) == LenHeader {
		return &Capdu{Cla: c[OffsetCla], Ins: c[OffsetIns], P1: c[OffsetP1], P2: c[OffsetP2]}, nil
	}

	// check for zero byte
	if c[OffsetLcStandard] == 0x00 {
		// check for extended length Capdu
		if len(c[OffsetLcExtended:]) > 0 {
			// EXTENDED CASE 2 command: HEADER | LE
			// in this case no LC is present, but the two byte LE with leading zero byte
			if len(c) == LenHeader+LenLCExtended {
				ne := 0
				le := int(binary.BigEndian.Uint16(c[OffsetLcExtended:]))

				if le == 0x00 {
					ne = MaxLenResponseDataExtended
				} else {
					ne = le
				}

				return &Capdu{Cla: c[OffsetCla], Ins: c[OffsetIns], P1: c[OffsetP1], P2: c[OffsetP2], Ne: ne}, nil
			}

			bodyLen := len(c) - LenHeader

			lc := int(binary.BigEndian.Uint16(c[OffsetLcExtended : OffsetLcExtended+2]))
			if lc != bodyLen-LenLCExtended && lc != bodyLen-LenLCExtended-2 {
				return nil, errors.Errorf("%s: invalid LC value - LC indicates data length %d", packageTag, lc)
			}

			data := c[OffsetCdataExtended : OffsetCdataExtended+lc]

			// EXTENDED CASE 3 command: HEADER | LC | DATA
			if len(c) == LenHeader+LenLCExtended+len(data) {
				return &Capdu{Cla: c[OffsetCla], Ins: c[OffsetIns], P1: c[OffsetP1], P2: c[OffsetP2], Data: data, Ne: 0}, nil
			}

			// EXTENDED CASE 4 command: HEADER | LC | DATA | LE
			ne := 0

			le := int(binary.BigEndian.Uint16(c[len(c)-2:]))

			if le == 0x00 {
				ne = MaxLenResponseDataExtended
			} else {
				ne = le
			}

			return &Capdu{Cla: c[OffsetCla], Ins: c[OffsetIns], P1: c[OffsetP1], P2: c[OffsetP2], Data: data, Ne: ne}, nil
		}
	}

	ne := 0
	// STANDARD CASE 2 command: HEADER | LE
	if len(c) == LenHeader+LenLCStandard {
		// in this case, no LC is present
		ne = int(c[OffsetLcStandard])
		if ne == 0 {
			return &Capdu{Cla: c[OffsetCla], Ins: c[OffsetIns], P1: c[OffsetP1], P2: c[OffsetP2], Data: nil, Ne: MaxLenResponseDataStandard}, nil
		}

		return &Capdu{Cla: c[OffsetCla], Ins: c[OffsetIns], P1: c[OffsetP1], P2: c[OffsetP2], Data: nil, Ne: ne}, nil
	}

	bodyLen := len(c) - LenHeader

	// check if lc indicates valid length
	lc := int(c[OffsetLcStandard])
	if lc != bodyLen-LenLCStandard && lc != bodyLen-LenLCStandard-1 {
		return nil, errors.Errorf("%s: invalid Lc value - Lc indicates length %d", packageTag, lc)
	}

	data := c[OffsetCdataStandard : OffsetCdataStandard+lc]

	// STANDARD CASE 3 command: HEADER | LC | DATA
	if len(c) == LenHeader+LenLCStandard+len(data) {
		return &Capdu{Cla: c[OffsetCla], Ins: c[OffsetIns], P1: c[OffsetP1], P2: c[OffsetP2], Data: data}, nil
	}

	// STANDARD CASE 4 command: HEADER | LC | DATA | LE
	if le := int(c[len(c)-1]); le == 0 {
		ne = MaxLenResponseDataStandard
	} else {
		ne = le
	}

	return &Capdu{Cla: c[OffsetCla], Ins: c[OffsetIns], P1: c[OffsetP1], P2: c[OffsetP2], Data: data, Ne: ne}, nil
}

// ParseCapduHexString decodes the hex-string representation of a Command APDU, calls ParseCapdu and returns a Capdu.
func ParseCapduHexString(s string) (*Capdu, error) {
	if len(s)%2 != 0 {
		return nil, errors.Errorf("%s: uneven number of hex characters", packageTag)
	}

	if len(s) < 8 || len(s) > 131088 {
		return nil, errors.Errorf("%s: invalid length of hex string - a Capdu must consist of at least 4 byte and maximum of 65544 byte, got %d", packageTag, len(s)/2)
	}

	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, errors.Wrapf(err, "%s: hex conversion error", packageTag)
	}

	return ParseCapdu(b)
}

// Bytes returns the byte representation of the Capdu.
func (c *Capdu) Bytes() ([]byte, error) {
	dataLen := len(c.Data)

	if dataLen > MaxLenCommandDataExtended {
		return nil, errors.Errorf("%s: len of Capdu.Data %d exceeds maximum allowed length of %d",
			packageTag, len(c.Data), MaxLenCommandDataExtended)
	}

	if c.Ne > MaxLenResponseDataExtended {
		return nil, errors.Errorf("%s: ne %d exceeds maximum allowed length of %d",
			packageTag, len(c.Data), MaxLenResponseDataExtended)
	}

	ca := c.determineCase()

	switch ca {
	case 1:
		return []byte{c.Cla, c.Ins, c.P1, c.P2}, nil
	case 2:
		// CASE 2: HEADER | LE
		if c.Ne > MaxLenResponseDataStandard {
			le := make([]byte, LenLCExtended) // first byte is zero byte, so LE length is equal to LC length

			if c.Ne == MaxLenResponseDataExtended {
				le[1] = 0x00
				le[2] = 0x00
			} else {
				le[1] = (byte)((c.Ne >> 8) & 0xFF)
				le[2] = (byte)(c.Ne & 0xFF)
			}

			result := make([]byte, 0, LenHeader+LenLCExtended)
			result = append(result, []byte{c.Cla, c.Ins, c.P1, c.P2}...)
			result = append(result, le...)

			return result, nil
		}

		//standard format
		result := make([]byte, 0, LenHeader+LenLCStandard)
		result = append(result, []byte{c.Cla, c.Ins, c.P1, c.P2}...)

		if c.Ne == MaxLenResponseDataStandard {
			result = append(result, 0x00)
		} else {
			result = append(result, byte(c.Ne))
		}

		return result, nil
	case 3:
		// CASE 3: HEADER | LC | DATA
		if len(c.Data) > MaxLenCommandDataStandard {
			// extended length format
			lc := make([]byte, LenLCExtended)
			lc[1] = (byte)((dataLen >> 8) & 0xFF)
			lc[2] = (byte)(dataLen & 0xFF)

			result := make([]byte, 0, LenHeader+LenLCExtended+dataLen)
			result = append(result, []byte{c.Cla, c.Ins, c.P1, c.P2}...)
			result = append(result, lc...)
			result = append(result, c.Data...)

			return result, nil
		}

		//standard format
		result := make([]byte, 0, LenHeader+1+dataLen)
		result = append(result, []byte{c.Cla, c.Ins, c.P1, c.P2, byte(dataLen)}...)
		result = append(result, c.Data...)

		return result, nil
	}

	// CASE 4: HEADER | LC | DATA | LE
	if c.Ne > MaxLenResponseDataStandard || len(c.Data) > MaxLenCommandDataStandard {
		// extended length format
		lc := make([]byte, LenLCExtended) // first byte is zero byte
		lc[1] = (byte)((dataLen >> 8) & 0xFF)
		lc[2] = (byte)(dataLen & 0xFF)

		le := make([]byte, 2)

		if c.Ne == MaxLenResponseDataExtended {
			le[0] = 0x00
			le[1] = 0x00
		} else {
			le[0] = (byte)((c.Ne >> 8) & 0xFF)
			le[1] = (byte)(c.Ne & 0xFF)
		}

		result := make([]byte, 0, LenHeader+LenLCExtended+dataLen+len(le))
		result = append(result, []byte{c.Cla, c.Ins, c.P1, c.P2}...)
		result = append(result, lc...)
		result = append(result, c.Data...)
		result = append(result, le...)

		return result, nil
	}

	//standard format
	result := make([]byte, 0, LenHeader+LenLCStandard+dataLen+1)
	result = append(result, []byte{c.Cla, c.Ins, c.P1, c.P2, byte(dataLen)}...)
	result = append(result, c.Data...)
	result = append(result, byte(c.Ne))

	return result, nil
}

func (c *Capdu) determineCase() int {
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

// String calls Bytes and returns the hex encoded string representation of the Capdu.
func (c *Capdu) String() (string, error) {
	b, err := c.Bytes()
	if err != nil {
		return "", err
	}

	return strings.ToUpper(hex.EncodeToString(b)), nil
}

// IsExtendedLength returns true if the Capdu has extended length (len of Data > 65535 or Ne > 65536), else false.
func (c *Capdu) IsExtendedLength() bool {
	return c.Ne > MaxLenResponseDataStandard || len(c.Data) > MaxLenCommandDataStandard
}

// Rapdu is a Response APDU.
type Rapdu struct {
	Data []byte // Data is the data field.
	SW1  byte   // SW1 is the first byte of a status word.
	SW2  byte   // SW2 is the second byte of a status word.
}

// ParseRapdu parses a Response APDU and returns a Rapdu.
func ParseRapdu(b []byte) (*Rapdu, error) {
	if len(b) < LenResponseTrailer || len(b) > 65538 {
		return nil, errors.Errorf("%s: invalid length - a RAPDU must consist of at least 2 byte and maximum of 65538 byte, got %d", packageTag, len(b))
	}

	if len(b) == LenResponseTrailer {
		return &Rapdu{SW1: b[0], SW2: b[1]}, nil
	}

	return &Rapdu{Data: b[:len(b)-LenResponseTrailer], SW1: b[len(b)-2], SW2: b[len(b)-1]}, nil
}

// ParseRapduHexString decodes the hex-string representation of a Response APDU, calls ParseRapdu and returns a Rapdu.
func ParseRapduHexString(s string) (*Rapdu, error) {
	if len(s)%2 != 0 {
		return nil, errors.Errorf("%s: uneven number of hex characters", packageTag)
	}

	if len(s) < 4 || len(s) > 131076 {
		return nil, errors.Errorf("%s: invalid length of hex string - a RAPDU must consist of at least 2 byte and maximum of 65538 byte, got %d", packageTag, len(s)/2)
	}

	tmp, err := hex.DecodeString(s)
	if err != nil {
		return nil, errors.Wrapf(err, "%s: hex conversion error", packageTag)
	}

	return ParseRapdu(tmp)
}

// Bytes returns the byte representation of the RAPDU.
func (r *Rapdu) Bytes() ([]byte, error) {
	if len(r.Data) > MaxLenResponseDataExtended {
		return nil, errors.Errorf("%s: len of Rapdu.Data %d exceeds maximum allowed length of %d",
			packageTag, len(r.Data), MaxLenResponseDataExtended)
	}

	b := make([]byte, 0, len(r.Data)+2)
	b = append(b, r.Data...)
	b = append(b, []byte{r.SW1, r.SW2}...)

	return b, nil
}

// String calls Bytes and returns the hex encoded string representation of the RAPDU.
func (r *Rapdu) String() (string, error) {
	b, err := r.Bytes()
	if err != nil {
		return "", err
	}

	return strings.ToUpper(hex.EncodeToString(b)), nil
}

// IsSuccess returns true if the RAPDU indicates the successful execution of a command ('0x61xx' or '0x9000'), otherwise false.
func (r *Rapdu) IsSuccess() bool {
	return r.SW1 == 0x61 || r.SW1 == 0x90 && r.SW2 == 0x00
}

// IsWarning returns true if the RAPDU indicates the execution of a command with a warning ('0x62xx' or '0x63xx'), otherwise false.
func (r *Rapdu) IsWarning() bool {
	return r.SW1 == 0x62 || r.SW1 == 0x63
}

// IsError returns true if the RAPDU indicates an error during the execution of a command ('0x64xx', '0x65xx' or from '0x67xx' to 0x6Fxx'), otherwise false.
func (r *Rapdu) IsError() bool {
	return (r.SW1 == 0x64 || r.SW1 == 0x65) || (r.SW1 >= 0x67 && r.SW1 <= 0x6F)
}
