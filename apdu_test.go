package apdu

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestParseCapdu(t *testing.T) {
	tests := []struct {
		name        string
		inputBytes  []byte
		expected    Capdu
		expectError bool
	}{
		{name: "Unhappy path: invalid length",
			inputBytes:  []byte{0x00, 0xA4, 0x04},
			expected:    Capdu{},
			expectError: true,
		},
		{name: "Unhappy path: standard length LC too big",
			inputBytes:  []byte{0x00, 0xA4, 0x04, 0x01, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			expected:    Capdu{},
			expectError: true,
		},
		{name: "Unhappy path: extended length LC too big",
			inputBytes:  []byte{0x00, 0xA4, 0x04, 0x01, 0x00, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04},
			expected:    Capdu{},
			expectError: true,
		},
		{name: "Unhappy path: extended length LC too small",
			inputBytes:  []byte{0x00, 0xA4, 0x04, 0x01, 0x00, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			expected:    Capdu{},
			expectError: true,
		},
		{name: "Happy path: Case 1",
			inputBytes:  []byte{0x00, 0xA4, 0x04, 0x00},
			expected:    Capdu{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x00, Ne: 0},
			expectError: false,
		},
		{name: "Happy path: Case 2 standard length LE equal zero",
			inputBytes:  []byte{0x00, 0xA4, 0x04, 0x00, 0x00},
			expected:    Capdu{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x00, Ne: 256},
			expectError: false,
		},
		{name: "Happy path: Case 2 standard length LE unequal zero",
			inputBytes:  []byte{0x00, 0xA4, 0x04, 0x00, 0x05},
			expected:    Capdu{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x00, Ne: 5},
			expectError: false,
		},
		{name: "Happy path: Case 2 extended length LE equal zero",
			inputBytes:  []byte{0x00, 0xA4, 0x04, 0x00, 0x00, 0x00, 0x00},
			expected:    Capdu{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x00, Ne: 65536},
			expectError: false,
		},
		{name: "Happy path: Case 2 extended length LE unequal zero",
			inputBytes:  []byte{0x00, 0xA4, 0x04, 0x00, 0x00, 0x01, 0x01},
			expected:    Capdu{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x00, Ne: 257},
			expectError: false,
		},
		{name: "Happy path: Case 3 standard length",
			inputBytes:  []byte{0x00, 0xA4, 0x04, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05},
			expected:    Capdu{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x00, Data: []byte{0x01, 0x02, 0x03, 0x04, 0x05}, Ne: 0},
			expectError: false,
		},
		{name: "Happy path: extended length CASE 3",
			inputBytes:  []byte{0x00, 0xA4, 0x04, 0x01, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03},
			expected:    Capdu{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x01, Data: []byte{0x01, 0x02, 0x03}, Ne: 0},
			expectError: false,
		},
		{name: "Happy path: Case 4 standard length  LE equal zero",
			inputBytes:  []byte{0x00, 0xA4, 0x04, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x00},
			expected:    Capdu{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x00, Data: []byte{0x01, 0x02, 0x03, 0x04, 0x05}, Ne: 256},
			expectError: false,
		},
		{name: "Happy path: Case 4 standard length  LE unequal zero",
			inputBytes:  []byte{0x00, 0xA4, 0x04, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x20},
			expected:    Capdu{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x00, Data: []byte{0x01, 0x02, 0x03, 0x04, 0x05}, Ne: 32},
			expectError: false,
		},
		{name: "Happy path: extended length CASE 4 LE equal zero",
			inputBytes:  []byte{0x00, 0xA4, 0x04, 0x01, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03, 0x00, 0x00},
			expected:    Capdu{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x01, Data: []byte{0x01, 0x02, 0x03}, Ne: 65536},
			expectError: false,
		},
		{name: "Happy path: extended length CASE 4 LE unequal zero",
			inputBytes:  []byte{0x00, 0xA4, 0x04, 0x01, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03, 0x01, 0x01},
			expected:    Capdu{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x01, Data: []byte{0x01, 0x02, 0x03}, Ne: 257},
			expectError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received, err := ParseCapdu(tc.inputBytes)
			if err != nil && !tc.expectError {
				t.Errorf("Expected: no error, got: error(%v)", err.Error())

				return
			}

			if err == nil && tc.expectError {
				t.Errorf("Expected: error, got: no error")

				return
			}

			if !cmp.Equal(received, tc.expected) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestParseCapduHexString(t *testing.T) {
	longData := make([]byte, 300)
	for i := range longData {
		longData[i] = 0xFF
	}

	tests := []struct {
		name        string
		inputString string
		expected    Capdu
		expectError bool
	}{
		{name: "Unhappy path: uneven number bytes",
			inputString: "000102030",
			expected:    Capdu{},
			expectError: true,
		},
		{name: "Unhappy path: invalid length",
			inputString: "000102",
			expected:    Capdu{},
			expectError: true,
		},
		{name: "Unhappy path: invalid characters",
			inputString: "00010203GG",
			expected:    Capdu{},
			expectError: true,
		},
		{name: "Happy path: standard length CASE 1",
			inputString: "00A40401",
			expected:    Capdu{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x01, Ne: 0},
			expectError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received, err := ParseCapduHexString(tc.inputString)
			if err != nil && !tc.expectError {
				t.Errorf("Expected: no error, got: error(%v)", err.Error())

				return
			}

			if err == nil && tc.expectError {
				t.Errorf("Expected: error, got: no error")

				return
			}

			if !cmp.Equal(received, tc.expected) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestParseRapdu(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		expected    Rapdu
		expectError bool
	}{
		{name: "Unhappy path: invalid length too small",
			input:    []byte{0x6A},
			expected: Rapdu{}, expectError: true},
		{name: "Unhappy path: invalid length too big",
			input:    make([]byte, 65539),
			expected: Rapdu{}, expectError: true},
		{name: "Happy path: only SW",
			input:    []byte{0x6A, 0x80},
			expected: Rapdu{Data: nil, SW1: 0x6A, SW2: 0x80}, expectError: false},
		{name: "Happy path: data and SW",
			input:    []byte{0x01, 0x02, 0x03, 0x90, 0x00},
			expected: Rapdu{Data: []byte{0x01, 0x02, 0x03}, SW1: 0x90, SW2: 0x00}, expectError: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received, err := ParseRapdu(tc.input)
			if err != nil && !tc.expectError {
				t.Errorf("Expected: no error, got: error(%v)", err.Error())

				return
			}

			if err == nil && tc.expectError {
				t.Errorf("Expected: error, got: no error")

				return
			}

			if !cmp.Equal(received, tc.expected) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestParseRapduHexString(t *testing.T) {
	tests := []struct {
		name        string
		inputString string
		expected    Rapdu
		expectError bool
	}{
		{name: "Unhappy path: uneven number bytes",
			inputString: "6A80A",
			expected:    Rapdu{}, expectError: true},
		{name: "Unhappy path: invalid length",
			inputString: "6A",
			expected:    Rapdu{}, expectError: true},
		{name: "Unhappy path: invalid characters",
			inputString: "FFGF6A88",
			expected:    Rapdu{}, expectError: true},
		{name: "Happy path: only SW",
			inputString: "6A80",
			expected:    Rapdu{Data: nil, SW1: 0x6A, SW2: 0x80}, expectError: false},
		{name: "Happy path: data and SW",
			inputString: "0102039000",
			expected:    Rapdu{Data: []byte{0x01, 0x02, 0x03}, SW1: 0x90, SW2: 0x00}, expectError: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received, err := ParseRapduHexString(tc.inputString)
			if err != nil && !tc.expectError {
				t.Errorf("Expected: no error, got: error(%v)", err.Error())

				return
			}

			if err == nil && tc.expectError {
				t.Errorf("Expected: error, got: no error")

				return
			}

			if !cmp.Equal(received, tc.expected) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestCapdu_Bytes(t *testing.T) {
	extendedData := make([]byte, 65535)
	for i := range extendedData {
		extendedData[i] = 0xFF
	}

	tooExtendedData := append(extendedData, 0xFF)

	tests := []struct {
		name     string
		capdu    Capdu
		expected []byte
	}{
		{name: "standard length CASE 1",
			capdu:    Capdu{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x01, Ne: 0},
			expected: []byte{0x00, 0xA4, 0x04, 0x01},
		},
		{name: "standard length CASE 2 LE unequal zero",
			capdu:    Capdu{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x01, Ne: 255},
			expected: []byte{0x00, 0xA4, 0x04, 0x01, 0xFF},
		},
		{name: "standard length CASE 2 LE equal zero",
			capdu:    Capdu{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x01, Ne: 256},
			expected: []byte{0x00, 0xA4, 0x04, 0x01, 0x00},
		},
		{name: "standard length CASE 3",
			capdu:    Capdu{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x01, Data: []byte{0x01, 0x02, 0x3}, Ne: 0},
			expected: []byte{0x00, 0xA4, 0x04, 0x01, 0x03, 0x01, 0x02, 0x03},
		},
		{name: "standard length CASE 4",
			capdu:    Capdu{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x01, Data: []byte{0x01, 0x02}, Ne: 3},
			expected: []byte{0x00, 0xA4, 0x04, 0x01, 0x02, 0x01, 0x02, 0x03},
		},
		{name: "extended length CASE 2 LE unequal zero",
			capdu:    Capdu{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x01, Ne: 65535},
			expected: []byte{0x00, 0xA4, 0x04, 0x01, 0x00, 0xFF, 0xFF},
		},
		{name: "extended length CASE 2 LE equal zero",
			capdu:    Capdu{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x01, Ne: 65536},
			expected: []byte{0x00, 0xA4, 0x04, 0x01, 0x00, 0x00, 0x00},
		},
		{name: "truncate ne extended length CASE 2",
			capdu:    Capdu{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x01, Ne: 65537},
			expected: []byte{0x00, 0xA4, 0x04, 0x01, 0x00, 0x00, 0x00},
		},
		{name: "extended length CASE 3",
			capdu:    Capdu{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x01, Data: extendedData, Ne: 0},
			expected: append([]byte{0x00, 0xA4, 0x04, 0x01, 0x00, 0xFF, 0xFF}, extendedData...),
		},
		{name: "truncate data extended length CASE 3",
			capdu:    Capdu{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x01, Data: tooExtendedData, Ne: 0},
			expected: append([]byte{0x00, 0xA4, 0x04, 0x01, 0x00, 0xFF, 0xFF}, extendedData...)},
		{name: "extended length CASE 4 LE unequal zero",
			capdu:    Capdu{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x01, Data: extendedData, Ne: 65535},
			expected: append(append([]byte{0x00, 0xA4, 0x04, 0x01, 0x00, 0xFF, 0xFF}, extendedData...), []byte{0xFF, 0xFF}...),
		},
		{name: "extended length CASE 4 LE equal zero",
			capdu:    Capdu{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x01, Data: extendedData, Ne: 65536},
			expected: append(append([]byte{0x00, 0xA4, 0x04, 0x01, 0x00, 0xFF, 0xFF}, extendedData...), []byte{0x00, 0x00}...),
		},
		{name: "truncate data extended length CASE 4",
			capdu:    Capdu{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x01, Data: tooExtendedData, Ne: 255},
			expected: append(append([]byte{0x00, 0xA4, 0x04, 0x01, 0x00, 0xFF, 0xFF}, extendedData...), []byte{0x00, 0xFF}...),
		},
		{name: "truncate ne extended length CASE 4",
			capdu:    Capdu{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x01, Data: tooExtendedData, Ne: 65537},
			expected: append(append([]byte{0x00, 0xA4, 0x04, 0x01, 0x00, 0xFF, 0xFF}, extendedData...), []byte{0x00, 0x00}...),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := tc.capdu.Bytes()

			if !cmp.Equal(received, tc.expected) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestCapdu_IsExtendedLength(t *testing.T) {
	extendedData := make([]byte, 256)
	for i := range extendedData {
		extendedData[i] = 0xFF
	}

	standardData := make([]byte, 255)
	for i := range standardData {
		standardData[i] = 0xFF
	}

	tests := []struct {
		name     string
		capdu    Capdu
		expected bool
	}{
		{name: "extended length ne",
			capdu:    Capdu{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x01, Ne: 257},
			expected: true,
		},
		{name: "extended length data",
			capdu:    Capdu{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x01, Data: extendedData, Ne: 256},
			expected: true,
		},
		{name: "standard length",
			capdu:    Capdu{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x01, Data: standardData, Ne: 256},
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := tc.capdu.IsExtendedLength()

			if received != tc.expected {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestCapdu_Lc(t *testing.T) {
	extendedData := make([]byte, 256)
	for i := range extendedData {
		extendedData[i] = 0xFF
	}

	standardData := make([]byte, 255)
	for i := range standardData {
		standardData[i] = 0xFF
	}

	tests := []struct {
		name     string
		capdu    Capdu
		expected []byte
	}{
		{name: "no lc",
			capdu:    Capdu{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x01, Ne: 256},
			expected: nil,
		},
		{name: "extended length lc",
			capdu:    Capdu{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x01, Data: extendedData, Ne: 257},
			expected: []byte{0x00, 0x01, 0x00},
		},
		{name: "standard length lc",
			capdu:    Capdu{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x01, Data: standardData, Ne: 256},
			expected: []byte{0xFF},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := tc.capdu.Lc()

			if !bytes.Equal(received, tc.expected) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestCapdu_String(t *testing.T) {
	tests := []struct {
		name     string
		capdu    Capdu
		expected string
	}{
		{name: "to string",
			capdu:    Capdu{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x01, Data: []byte{0x01, 0x02}, Ne: 3},
			expected: "00A4040102010203"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := tc.capdu.String()

			if received != tc.expected {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestRapdu_Bytes(t *testing.T) {
	tooExtendedData := make([]byte, MaxLenResponseDataExtended+1)
	for i := range tooExtendedData {
		tooExtendedData[i] = 0xFF
	}

	tests := []struct {
		name     string
		rapdu    Rapdu
		expected []byte
	}{
		{name: "only SW",
			rapdu:    Rapdu{Data: nil, SW1: 0x6A, SW2: 0x80},
			expected: []byte{0x6A, 0x80},
		},
		{name: "data and SW",
			rapdu:    Rapdu{Data: []byte{0x01, 0x02, 0x03}, SW1: 0x90, SW2: 0x00},
			expected: []byte{0x01, 0x02, 0x03, 0x90, 0x00},
		},
		{name: "data and SW, truncate data",
			rapdu:    Rapdu{Data: tooExtendedData, SW1: 0x90, SW2: 0x00},
			expected: append(tooExtendedData[:len(tooExtendedData)-1], []byte{0x90, 0x00}...),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := tc.rapdu.Bytes()

			if !cmp.Equal(received, tc.expected) {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestRapdu_String(t *testing.T) {
	tests := []struct {
		name     string
		rapdu    Rapdu
		expected string
	}{
		{name: "sw only",
			rapdu:    Rapdu{Data: []byte{0x01, 0x02, 0x03}, SW1: 0x90, SW2: 0x00},
			expected: "0102039000"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := tc.rapdu.String()

			if received != tc.expected {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestRapdu_IsSuccess(t *testing.T) {
	tests := []struct {
		name     string
		rapdu    Rapdu
		expected bool
	}{
		{name: "sw only success",
			rapdu:    Rapdu{SW1: 0x90, SW2: 0x00},
			expected: true,
		},
		{name: "sw only success",
			rapdu:    Rapdu{SW1: 0x61, SW2: 0x10},
			expected: true,
		},
		{name: "sw only not success",
			rapdu:    Rapdu{SW1: 0x6A, SW2: 0x88},
			expected: false,
		},
		{name: "sw + data success",
			rapdu:    Rapdu{Data: []byte{0x01, 0x02, 0x03, 0x04}, SW1: 0x90, SW2: 0x00},
			expected: true,
		},
		{name: "sw + data success",
			rapdu:    Rapdu{Data: []byte{0x01, 0x02, 0x03, 0x04}, SW1: 0x61, SW2: 0x03},
			expected: true,
		},
		{name: "sw + data not success",
			rapdu:    Rapdu{Data: []byte{0x01, 0x02, 0x03, 0x04}, SW1: 0x6A, SW2: 0x88},
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := tc.rapdu.IsSuccess()

			if received != tc.expected {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestRapdu_IsWarning(t *testing.T) {
	tests := []struct {
		name     string
		rapdu    Rapdu
		expected bool
	}{
		{name: "warning 0x62",
			rapdu:    Rapdu{SW1: 0x62, SW2: 0x84},
			expected: true,
		},
		{name: "warning 0x63",
			rapdu:    Rapdu{SW1: 0x63, SW2: 0xC1},
			expected: true,
		},
		{name: "success, not warning",
			rapdu:    Rapdu{Data: []byte{0x01, 0x02, 0x03, 0x04}, SW1: 0x90, SW2: 0x00},
			expected: false,
		},
		{name: "error, not warning",
			rapdu:    Rapdu{SW1: 0x6F, SW2: 0x00},
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := tc.rapdu.IsWarning()

			if received != tc.expected {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}

func TestRapdu_IsError(t *testing.T) {
	tests := []struct {
		name     string
		rapdu    Rapdu
		expected bool
	}{
		{name: "error 0x64",
			rapdu:    Rapdu{SW1: 0x64, SW2: 0x00},
			expected: true,
		},
		{name: "error 0x65",
			rapdu:    Rapdu{SW1: 0x65, SW2: 0x81},
			expected: true,
		},
		{name: "error 0x67",
			rapdu:    Rapdu{SW1: 0x67, SW2: 0x00},
			expected: true,
		},
		{name: "error 0x6A",
			rapdu:    Rapdu{SW1: 0x6A, SW2: 0x88},
			expected: true,
		},
		{name: "error 0x6F",
			rapdu:    Rapdu{SW1: 0x6F, SW2: 0x00},
			expected: true,
		},
		{name: "success, not error",
			rapdu:    Rapdu{Data: []byte{0x01, 0x02, 0x03, 0x04}, SW1: 0x90, SW2: 0x00},
			expected: false,
		},
		{name: "warning, not error",
			rapdu:    Rapdu{SW1: 0x63, SW2: 0x00},
			expected: false,
		},
		{name: "no error, 0x66 sw",
			rapdu:    Rapdu{SW1: 0x66, SW2: 0x00},
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			received := tc.rapdu.IsError()

			if received != tc.expected {
				t.Errorf("Expected: '%v', got: '%v'", tc.expected, received)
			}
		})
	}
}
