package apdu_test

import (
	"errors"
	"fmt"

	"github.com/skythen/apdu"
)

func ExampleParseCapdu() {
	c, err := apdu.ParseCapdu([]byte{0x80, 0xF2, 0xE0, 0x02, 0x02, 0x4F, 0x00, 0x00})
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("CLA: %02X, INS: %02X, P1: %02X, P2: %02X, Data: %X, Ne: %d\n",
		c.Cla, c.Ins, c.P1, c.P2, c.Data, c.Ne)
	// Output: CLA: 80, INS: F2, P1: E0, P2: 02, Data: 4F00, Ne: 256
}

func ExampleParseCapduHexString() {
	c, err := apdu.ParseCapduHexString("80F2E002024F0000")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("CLA: %02X, INS: %02X, P1: %02X, P2: %02X, Data: %X, Ne: %d\n",
		c.Cla, c.Ins, c.P1, c.P2, c.Data, c.Ne)
	// Output: CLA: 80, INS: F2, P1: E0, P2: 02, Data: 4F00, Ne: 256
}

func ExampleCapdu_Bytes() {
	c := apdu.Capdu{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x00, Data: []byte{0xA0, 0x00, 0x00, 0x00, 0x03}, Ne: 256}
	b, err := c.Bytes()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("%X\n", b)
	// Output: 00A4040005A00000000300
}

func ExampleCapdu_String() {
	c := apdu.Capdu{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x00, Data: []byte{0xA0, 0x00, 0x00, 0x00, 0x03}}
	s, err := c.String()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(s)
	// Output: 00A4040005A000000003
}

func ExampleCapdu_IsExtendedLength() {
	standard := apdu.Capdu{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x00, Ne: 256}
	extended := apdu.Capdu{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x00, Ne: 65536}
	fmt.Println(standard.IsExtendedLength())
	fmt.Println(extended.IsExtendedLength())
	// Output:
	// false
	// true
}

func ExampleParseRapdu() {
	r, err := apdu.ParseRapdu([]byte{0x01, 0x02, 0x03, 0x90, 0x00})
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Data: %X, SW1: %02X, SW2: %02X\n", r.Data, r.SW1, r.SW2)
	// Output: Data: 010203, SW1: 90, SW2: 00
}

func ExampleParseRapduHexString() {
	r, err := apdu.ParseRapduHexString("0102039000")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Data: %X, SW1: %02X, SW2: %02X\n", r.Data, r.SW1, r.SW2)
	// Output: Data: 010203, SW1: 90, SW2: 00
}

func ExampleRapdu_Bytes() {
	r := apdu.Rapdu{Data: []byte{0x01, 0x02, 0x03}, SW1: 0x90, SW2: 0x00}
	b, err := r.Bytes()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("%X\n", b)
	// Output: 0102039000
}

func ExampleRapdu_String() {
	r := apdu.Rapdu{Data: []byte{0x01, 0x02, 0x03}, SW1: 0x90, SW2: 0x00}
	s, err := r.String()
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(s)
	// Output: 0102039000
}

func ExampleRapdu_IsSuccess() {
	r := apdu.Rapdu{SW1: 0x90, SW2: 0x00}
	fmt.Println(r.IsSuccess())
	// Output: true
}

func ExampleRapdu_IsWarning() {
	r := apdu.Rapdu{SW1: 0x62, SW2: 0x84}
	fmt.Println(r.IsWarning())
	// Output: true
}

func ExampleRapdu_IsError() {
	r := apdu.Rapdu{SW1: 0x6A, SW2: 0x82}
	fmt.Println(r.IsError())
	// Output: true
}

func ExampleParseCapdu_errorHandling() {
	_, err := apdu.ParseCapdu([]byte{0x00, 0xA4})
	if errors.Is(err, apdu.ErrInvalidLength) {
		fmt.Println("invalid length")
	}
	// Output: invalid length
}