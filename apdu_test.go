package apdu

import (
	"reflect"
	"testing"
)

func TestParseCapdu(t *testing.T) {
	type args struct {
		c []byte
	}

	tests := []struct {
		name    string
		args    args
		want    *Capdu
		wantErr bool
	}{
		{
			name:    "error: invalid length",
			args:    args{c: []byte{0x00, 0xA4, 0x04}},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "error: standard length LC too big",
			args:    args{[]byte{0x00, 0xA4, 0x04, 0x01, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "error: extended length LC too big",
			args:    args{[]byte{0x00, 0xA4, 0x04, 0x01, 0x00, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04}},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "error: extended length LC too small",
			args:    args{[]byte{0x00, 0xA4, 0x04, 0x01, 0x00, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "Case 1",
			args:    args{[]byte{0x00, 0xA4, 0x04, 0x00}},
			want:    &Capdu{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x00, Ne: 0},
			wantErr: false,
		},
		{
			name:    "Case 2 standard length LE equal zero",
			args:    args{[]byte{0x00, 0xA4, 0x04, 0x00, 0x00}},
			want:    &Capdu{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x00, Ne: 256},
			wantErr: false,
		},
		{
			name:    "Case 2 standard length LE unequal zero",
			args:    args{[]byte{0x00, 0xA4, 0x04, 0x00, 0x05}},
			want:    &Capdu{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x00, Ne: 5},
			wantErr: false,
		},
		{
			name:    "Case 2 extended length LE equal zero",
			args:    args{[]byte{0x00, 0xA4, 0x04, 0x00, 0x00, 0x00, 0x00}},
			want:    &Capdu{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x00, Ne: 65536},
			wantErr: false,
		},
		{
			name:    "Case 2 extended length LE unequal zero",
			args:    args{[]byte{0x00, 0xA4, 0x04, 0x00, 0x00, 0x01, 0x01}},
			want:    &Capdu{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x00, Ne: 257},
			wantErr: false,
		},
		{
			name:    "Case 3 standard length",
			args:    args{[]byte{0x00, 0xA4, 0x04, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05}},
			want:    &Capdu{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x00, Data: []byte{0x01, 0x02, 0x03, 0x04, 0x05}, Ne: 0},
			wantErr: false,
		},
		{
			name:    "extended length CASE 3",
			args:    args{[]byte{0x00, 0xA4, 0x04, 0x01, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03}},
			want:    &Capdu{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x01, Data: []byte{0x01, 0x02, 0x03}, Ne: 0},
			wantErr: false,
		},
		{
			name:    "Case 4 standard length  LE equal zero",
			args:    args{[]byte{0x00, 0xA4, 0x04, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x00}},
			want:    &Capdu{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x00, Data: []byte{0x01, 0x02, 0x03, 0x04, 0x05}, Ne: 256},
			wantErr: false,
		},
		{
			name:    "Case 4 standard length  LE unequal zero",
			args:    args{[]byte{0x00, 0xA4, 0x04, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x20}},
			want:    &Capdu{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x00, Data: []byte{0x01, 0x02, 0x03, 0x04, 0x05}, Ne: 32},
			wantErr: false,
		},
		{
			name:    "extended length CASE 4 LE equal zero",
			args:    args{[]byte{0x00, 0xA4, 0x04, 0x01, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03, 0x00, 0x00}},
			want:    &Capdu{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x01, Data: []byte{0x01, 0x02, 0x03}, Ne: 65536},
			wantErr: false,
		},
		{
			name:    "extended length CASE 4 LE unequal zero",
			args:    args{[]byte{0x00, 0xA4, 0x04, 0x01, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03, 0x01, 0x01}},
			want:    &Capdu{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x01, Data: []byte{0x01, 0x02, 0x03}, Ne: 257},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCapdu(tt.args.c)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCapdu() error = %v, wantErr %v", err, tt.wantErr)

				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseCapdu() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseCapduHexString(t *testing.T) {
	type args struct {
		s string
	}

	tests := []struct {
		name    string
		args    args
		want    *Capdu
		wantErr bool
	}{
		{
			name:    "error: uneven number bytes",
			args:    args{s: "000102030"},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "error: invalid length",
			args:    args{s: "000102"},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "error: invalid characters",
			args:    args{"s:00010203GG"},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "standard length CASE 1",
			args:    args{s: "00A40401"},
			want:    &Capdu{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x01, Ne: 0},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCapduHexString(tt.args.s)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCapduHexString() error = %v, wantErr %v", err, tt.wantErr)

				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseCapduHexString() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseRapdu(t *testing.T) {
	type args struct {
		b []byte
	}

	tests := []struct {
		name    string
		args    args
		want    *Rapdu
		wantErr bool
	}{
		{
			name:    "error: invalid length too small",
			args:    args{b: []byte{0x6A}},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "error: invalid length too big",
			args:    args{b: make([]byte, 65539)},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "only SW",
			args:    args{b: []byte{0x6A, 0x80}},
			want:    &Rapdu{Data: nil, SW1: 0x6A, SW2: 0x80},
			wantErr: false,
		},
		{
			name:    "data and SW",
			args:    args{b: []byte{0x01, 0x02, 0x03, 0x90, 0x00}},
			want:    &Rapdu{Data: []byte{0x01, 0x02, 0x03}, SW1: 0x90, SW2: 0x00},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRapdu(tt.args.b)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRapdu() error = %v, wantErr %v", err, tt.wantErr)

				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseRapdu() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseRapduHexString(t *testing.T) {
	type args struct {
		s string
	}

	tests := []struct {
		name    string
		args    args
		want    *Rapdu
		wantErr bool
	}{
		{
			name:    "error: uneven number bytes",
			args:    args{s: "6A80A"},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "error: invalid length",
			args:    args{s: "6A"},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "error: invalid characters",
			args:    args{s: "FFGF6A88"},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "only SW",
			args:    args{s: "6A80"},
			want:    &Rapdu{Data: nil, SW1: 0x6A, SW2: 0x80},
			wantErr: false,
		},
		{
			name:    "data and SW",
			args:    args{s: "0102039000"},
			want:    &Rapdu{Data: []byte{0x01, 0x02, 0x03}, SW1: 0x90, SW2: 0x00},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRapduHexString(tt.args.s)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRapduHexString() error = %v, wantErr %v", err, tt.wantErr)

				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseRapduHexString() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCapdu_Bytes(t *testing.T) {
	extendedData := make([]byte, 65535)
	for i := range extendedData {
		extendedData[i] = 0xFF
	}

	tooExtendedData := make([]byte, 65536)

	type fields struct {
		Cla  byte
		Ins  byte
		P1   byte
		P2   byte
		Data []byte
		Ne   int
	}

	tests := []struct {
		name    string
		fields  fields
		want    []byte
		wantErr bool
	}{
		{
			name:    "standard length CASE 1",
			fields:  fields{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x01, Ne: 0},
			want:    []byte{0x00, 0xA4, 0x04, 0x01},
			wantErr: false,
		},
		{
			name:    "standard length CASE 2 LE unequal zero",
			fields:  fields{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x01, Ne: 255},
			want:    []byte{0x00, 0xA4, 0x04, 0x01, 0xFF},
			wantErr: false,
		},
		{
			name:    "standard length CASE 2 LE equal zero",
			fields:  fields{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x01, Ne: 256},
			want:    []byte{0x00, 0xA4, 0x04, 0x01, 0x00},
			wantErr: false,
		},
		{
			name:    "standard length CASE 3",
			fields:  fields{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x01, Data: []byte{0x01, 0x02, 0x3}, Ne: 0},
			want:    []byte{0x00, 0xA4, 0x04, 0x01, 0x03, 0x01, 0x02, 0x03},
			wantErr: false,
		},
		{
			name:    "standard length CASE 4",
			fields:  fields{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x01, Data: []byte{0x01, 0x02}, Ne: 3},
			want:    []byte{0x00, 0xA4, 0x04, 0x01, 0x02, 0x01, 0x02, 0x03},
			wantErr: false,
		},
		{
			name:    "extended length CASE 2 LE unequal zero",
			fields:  fields{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x01, Ne: 65535},
			want:    []byte{0x00, 0xA4, 0x04, 0x01, 0x00, 0xFF, 0xFF},
			wantErr: false,
		},
		{
			name:    "extended length CASE 2 LE equal zero",
			fields:  fields{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x01, Ne: 65536},
			want:    []byte{0x00, 0xA4, 0x04, 0x01, 0x00, 0x00, 0x00},
			wantErr: false,
		},
		{
			name:    "error: ne invalid CASE 2",
			fields:  fields{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x01, Ne: 65537},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "extended length CASE 3",
			fields:  fields{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x01, Data: extendedData, Ne: 0},
			want:    append([]byte{0x00, 0xA4, 0x04, 0x01, 0x00, 0xFF, 0xFF}, extendedData...),
			wantErr: false,
		},
		{
			name:    "error: invalid length CASE 3",
			fields:  fields{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x01, Data: tooExtendedData, Ne: 0},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "extended length CASE 4 LE unequal zero",
			fields:  fields{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x01, Data: extendedData, Ne: 65535},
			want:    append(append([]byte{0x00, 0xA4, 0x04, 0x01, 0x00, 0xFF, 0xFF}, extendedData...), []byte{0xFF, 0xFF}...),
			wantErr: false,
		},
		{
			name:    "extended length CASE 4 LE equal zero",
			fields:  fields{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x01, Data: extendedData, Ne: 65536},
			want:    append(append([]byte{0x00, 0xA4, 0x04, 0x01, 0x00, 0xFF, 0xFF}, extendedData...), []byte{0x00, 0x00}...),
			wantErr: false,
		},
		{
			name:    "error: data extended length CASE 4",
			fields:  fields{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x01, Data: tooExtendedData, Ne: 255},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "error: ne invalid length CASE 4",
			fields:  fields{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x01, Data: tooExtendedData, Ne: 65537},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Capdu{
				Cla:  tt.fields.Cla,
				Ins:  tt.fields.Ins,
				P1:   tt.fields.P1,
				P2:   tt.fields.P2,
				Data: tt.fields.Data,
				Ne:   tt.fields.Ne,
			}
			got, err := c.Bytes()
			if (err != nil) != tt.wantErr {
				t.Errorf("Bytes() error = %v, wantErr %v", err, tt.wantErr)

				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Bytes() got = %v, want %v", got, tt.want)
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

	type fields struct {
		Cla  byte
		Ins  byte
		P1   byte
		P2   byte
		Data []byte
		Ne   int
	}

	tests := []struct {
		name   string
		fields fields
		want   bool
	}{
		{
			name:   "extended length ne",
			fields: fields{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x01, Ne: 257},
			want:   true,
		},
		{
			name:   "extended length data",
			fields: fields{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x01, Data: extendedData, Ne: 256},
			want:   true,
		},
		{
			name:   "standard length",
			fields: fields{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x01, Data: standardData, Ne: 256},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Capdu{
				Cla:  tt.fields.Cla,
				Ins:  tt.fields.Ins,
				P1:   tt.fields.P1,
				P2:   tt.fields.P2,
				Data: tt.fields.Data,
				Ne:   tt.fields.Ne,
			}
			if got := c.IsExtendedLength(); got != tt.want {
				t.Errorf("IsExtendedLength() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCapdu_String(t *testing.T) {
	type fields struct {
		Cla  byte
		Ins  byte
		P1   byte
		P2   byte
		Data []byte
		Ne   int
	}

	tests := []struct {
		name    string
		fields  fields
		want    string
		wantErr bool
	}{
		{
			name:    "to string",
			fields:  fields{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x01, Data: []byte{0x01, 0x02}, Ne: 3},
			want:    "00A4040102010203",
			wantErr: false,
		},
		{
			name:    "error: invalid ne",
			fields:  fields{Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x01, Data: []byte{0x01, 0x02}, Ne: 65537},
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Capdu{
				Cla:  tt.fields.Cla,
				Ins:  tt.fields.Ins,
				P1:   tt.fields.P1,
				P2:   tt.fields.P2,
				Data: tt.fields.Data,
				Ne:   tt.fields.Ne,
			}
			got, err := c.String()
			if (err != nil) != tt.wantErr {
				t.Errorf("String() error = %v, wantErr %v", err, tt.wantErr)

				return
			}
			if got != tt.want {
				t.Errorf("String() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRapdu_Bytes(t *testing.T) {
	tooExtendedData := make([]byte, MaxLenResponseDataExtended+1)
	for i := range tooExtendedData {
		tooExtendedData[i] = 0xFF
	}

	type fields struct {
		Data []byte
		SW1  byte
		SW2  byte
	}

	tests := []struct {
		name    string
		fields  fields
		want    []byte
		wantErr bool
	}{
		{
			name:    "only SW",
			fields:  fields{Data: nil, SW1: 0x6A, SW2: 0x80},
			want:    []byte{0x6A, 0x80},
			wantErr: false,
		},
		{
			name:    "data and SW",
			fields:  fields{Data: []byte{0x01, 0x02, 0x03}, SW1: 0x90, SW2: 0x00},
			want:    []byte{0x01, 0x02, 0x03, 0x90, 0x00},
			wantErr: false,
		},
		{
			name:    "data and SW, truncate data",
			fields:  fields{Data: tooExtendedData, SW1: 0x90, SW2: 0x00},
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Rapdu{
				Data: tt.fields.Data,
				SW1:  tt.fields.SW1,
				SW2:  tt.fields.SW2,
			}
			got, err := r.Bytes()
			if (err != nil) != tt.wantErr {
				t.Errorf("Bytes() error = %v, wantErr %v", err, tt.wantErr)

				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Bytes() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRapdu_String(t *testing.T) {
	type fields struct {
		Data []byte
		SW1  byte
		SW2  byte
	}

	tests := []struct {
		name    string
		fields  fields
		want    string
		wantErr bool
	}{
		{
			name:    "trailer only",
			fields:  fields{Data: []byte{0x01, 0x02, 0x03}, SW1: 0x90, SW2: 0x00},
			want:    "0102039000",
			wantErr: false,
		},
		{
			name:    "error: invalid length",
			fields:  fields{Data: make([]byte, 65537), SW1: 0x90, SW2: 0x00},
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Rapdu{
				Data: tt.fields.Data,
				SW1:  tt.fields.SW1,
				SW2:  tt.fields.SW2,
			}
			got, err := r.String()
			if (err != nil) != tt.wantErr {
				t.Errorf("String() error = %v, wantErr %v", err, tt.wantErr)

				return
			}
			if got != tt.want {
				t.Errorf("String() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRapdu_IsSuccess(t *testing.T) {
	type fields struct {
		Data []byte
		SW1  byte
		SW2  byte
	}

	tests := []struct {
		name   string
		fields fields
		want   bool
	}{
		{
			name:   "trailer only success",
			fields: fields{SW1: 0x90, SW2: 0x00},
			want:   true,
		},
		{
			name:   "trailer only success",
			fields: fields{SW1: 0x61, SW2: 0x10},
			want:   true,
		},
		{
			name:   "trailer only not success",
			fields: fields{SW1: 0x6A, SW2: 0x88},
			want:   false,
		},
		{
			name:   "trailer + data success",
			fields: fields{Data: []byte{0x01, 0x02, 0x03, 0x04}, SW1: 0x90, SW2: 0x00},
			want:   true,
		},
		{
			name:   "trailer + data success",
			fields: fields{Data: []byte{0x01, 0x02, 0x03, 0x04}, SW1: 0x61, SW2: 0x03},
			want:   true,
		},
		{
			name:   "trailer + data not success",
			fields: fields{Data: []byte{0x01, 0x02, 0x03, 0x04}, SW1: 0x6A, SW2: 0x88},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Rapdu{
				Data: tt.fields.Data,
				SW1:  tt.fields.SW1,
				SW2:  tt.fields.SW2,
			}
			if got := r.IsSuccess(); got != tt.want {
				t.Errorf("IsSuccess() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRapdu_IsWarning(t *testing.T) {
	type fields struct {
		Data []byte
		SW1  byte
		SW2  byte
	}

	tests := []struct {
		name   string
		fields fields
		want   bool
	}{
		{
			name:   "warning 0x62",
			fields: fields{SW1: 0x62, SW2: 0x84},
			want:   true,
		},
		{
			name:   "warning 0x63",
			fields: fields{SW1: 0x63, SW2: 0xC1},
			want:   true,
		},
		{
			name:   "success, not warning",
			fields: fields{Data: []byte{0x01, 0x02, 0x03, 0x04}, SW1: 0x90, SW2: 0x00},
			want:   false,
		},
		{
			name:   "error, not warning",
			fields: fields{SW1: 0x6F, SW2: 0x00},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Rapdu{
				Data: tt.fields.Data,
				SW1:  tt.fields.SW1,
				SW2:  tt.fields.SW2,
			}
			if got := r.IsWarning(); got != tt.want {
				t.Errorf("IsWarning() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRapdu_IsError(t *testing.T) {
	type fields struct {
		Data []byte
		SW1  byte
		SW2  byte
	}

	tests := []struct {
		name   string
		fields fields
		want   bool
	}{
		{
			name:   "error 0x64",
			fields: fields{SW1: 0x64, SW2: 0x00},
			want:   true,
		},
		{
			name:   "error 0x65",
			fields: fields{SW1: 0x65, SW2: 0x81},
			want:   true,
		},
		{
			name:   "error 0x67",
			fields: fields{SW1: 0x67, SW2: 0x00},
			want:   true,
		},
		{
			name:   "error 0x6A",
			fields: fields{SW1: 0x6A, SW2: 0x88},
			want:   true,
		},
		{
			name:   "error 0x6F",
			fields: fields{SW1: 0x6F, SW2: 0x00},
			want:   true,
		},
		{
			name:   "success, not error",
			fields: fields{Data: []byte{0x01, 0x02, 0x03, 0x04}, SW1: 0x90, SW2: 0x00},
			want:   false,
		},
		{
			name:   "warning, not error",
			fields: fields{SW1: 0x63, SW2: 0x00},
			want:   false,
		},
		{
			name:   "no error, 0x66",
			fields: fields{SW1: 0x66, SW2: 0x00},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Rapdu{
				Data: tt.fields.Data,
				SW1:  tt.fields.SW1,
				SW2:  tt.fields.SW2,
			}
			if got := r.IsError(); got != tt.want {
				t.Errorf("IsError() = %v, want %v", got, tt.want)
			}
		})
	}
}

// BENCHMARKS ----------------------------------------------------------------------------------------------------------
var resultCapdu *Capdu

func benchmarkParseCapdu(by []byte, b *testing.B) {
	var r *Capdu

	b.ReportAllocs()

	for n := 0; n < b.N; n++ {
		r, _ = ParseCapdu(by)
	}

	resultCapdu = r
}

func BenchmarkParseCapduCase1(b *testing.B) { benchmarkParseCapdu([]byte{0x00, 0xAA, 0xBB, 0xCC}, b) }
func BenchmarkParseCapduCase2Std(b *testing.B) {
	benchmarkParseCapdu([]byte{0x00, 0xAA, 0xBB, 0xCC, 0xDD}, b)
}
func BenchmarkParseCapduCase3Std(b *testing.B) {
	benchmarkParseCapdu([]byte{0x00, 0xAA, 0xBB, 0xCC, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05}, b)
}
func BenchmarkParseCapduCase4Std(b *testing.B) {
	benchmarkParseCapdu([]byte{0x00, 0xAA, 0xBB, 0xCC, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0xFF}, b)
}
func BenchmarkParseCapduCase2Ext(b *testing.B) {
	benchmarkParseCapdu([]byte{0x00, 0xAA, 0xBB, 0xCC, 0x00, 0xDD, 0xEE}, b)
}
func BenchmarkParseCapduCase3Ext(b *testing.B) {
	benchmarkParseCapdu([]byte{0x00, 0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05}, b)
}
func BenchmarkParseCapduCase4Ext(b *testing.B) {
	benchmarkParseCapdu([]byte{0x00, 0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x00, 0xFF}, b)
}

func benchmarkParseCapduHexString(s string, b *testing.B) {
	var r *Capdu

	b.ReportAllocs()

	for n := 0; n < b.N; n++ {
		r, _ = ParseCapduHexString(s)
	}

	resultCapdu = r
}

func BenchmarkParseCapduHexStringCase1(b *testing.B) { benchmarkParseCapduHexString("00AABBCC", b) }
func BenchmarkParseCapduHexStringCase2Std(b *testing.B) {
	benchmarkParseCapduHexString("00AABBCCDD", b)
}
func BenchmarkParseCapduHexStringCase3Std(b *testing.B) {
	benchmarkParseCapduHexString("00AABBCC050102030405", b)
}
func BenchmarkParseCapduHexStringCase4Std(b *testing.B) {
	benchmarkParseCapduHexString("00AABBCC050102030405FF", b)
}
func BenchmarkParseCapduHexStringCase2Ext(b *testing.B) {
	benchmarkParseCapduHexString("00AABBCC00DDEE", b)
}
func BenchmarkParseCapduHexStringCase3Ext(b *testing.B) {
	benchmarkParseCapduHexString("00AABBCC0000050102030405", b)
}
func BenchmarkParseCapduHexStringCase4Ext(b *testing.B) {
	benchmarkParseCapduHexString("00AABBCC000005010203040500FF", b)
}

var resultBytes []byte

func benchmarkCapduBytes(c Capdu, b *testing.B) {
	var r []byte

	b.ReportAllocs()

	for n := 0; n < b.N; n++ {
		r, _ = c.Bytes()
	}

	resultBytes = r
}

func BenchmarkCapdu_BytesCase1(b *testing.B) {
	benchmarkCapduBytes(Capdu{Cla: 0x00, Ins: 0xAA, P1: 0xBB, P2: 0xCC}, b)
}
func BenchmarkCapdu_BytesCase2Std(b *testing.B) {
	benchmarkCapduBytes(Capdu{Cla: 0x00, Ins: 0xAA, P1: 0xBB, P2: 0xCC, Ne: 0xDD}, b)
}
func BenchmarkCapdu_BytesCase3Std(b *testing.B) {
	benchmarkCapduBytes(Capdu{Cla: 0x00, Ins: 0xAA, P1: 0xBB, P2: 0xCC, Data: []byte{0x01, 0x02, 0x03, 0x04, 0x05}}, b)
}
func BenchmarkCapdu_BytesCase4Std(b *testing.B) {
	benchmarkCapduBytes(Capdu{Cla: 0x00, Ins: 0xAA, P1: 0xBB, P2: 0xCC, Data: []byte{0x01, 0x02, 0x03, 0x04, 0x05}, Ne: 255}, b)
}
func BenchmarkCapdu_BytesCase2Ext(b *testing.B) {
	benchmarkCapduBytes(Capdu{Cla: 0x00, Ins: 0xAA, P1: 0xBB, P2: 0xCC, Ne: 65535}, b)
}
func BenchmarkCapdu_BytesCase3Ext(b *testing.B) {
	benchmarkCapduBytes(Capdu{Cla: 0x00, Ins: 0xAA, P1: 0xBB, P2: 0xCC, Data: make([]byte, 256)}, b)
}
func BenchmarkCapdu_BytesCase4Ext(b *testing.B) {
	benchmarkCapduBytes(Capdu{Cla: 0x00, Ins: 0xAA, P1: 0xBB, P2: 0xCC, Data: make([]byte, 256), Ne: 65536}, b)
}

var resultRapdu *Rapdu

func benchmarkParseRapdu(by []byte, b *testing.B) {
	var r *Rapdu

	b.ReportAllocs()

	for n := 0; n < b.N; n++ {
		r, _ = ParseRapdu(by)
	}

	resultRapdu = r
}

func BenchmarkParseRapduTrailerOnly(b *testing.B) { benchmarkParseRapdu([]byte{0x90, 0x00}, b) }
func BenchmarkParseRapduTrailerAndData(b *testing.B) {
	benchmarkParseRapdu([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x90, 0x00}, b)
}

func benchmarkParseRapduHexString(s string, b *testing.B) {
	var r *Rapdu

	b.ReportAllocs()

	for n := 0; n < b.N; n++ {
		r, _ = ParseRapduHexString(s)
	}

	resultRapdu = r
}

func BenchmarkParseRapduHexStringTrailerOnly(b *testing.B) { benchmarkParseRapduHexString("9000", b) }
func BenchmarkParseRapduHexStringTrailerAndData(b *testing.B) {
	benchmarkParseRapduHexString("01020304059000", b)
}

func benchmarkRapduBytes(c Rapdu, b *testing.B) {
	var r []byte

	b.ReportAllocs()

	for n := 0; n < b.N; n++ {
		r, _ = c.Bytes()
	}

	resultBytes = r
}

func BenchmarkRapdu_BytesOTrailerOnly(b *testing.B) {
	benchmarkRapduBytes(Rapdu{SW1: 0x90, SW2: 0x00}, b)
}
func BenchmarkRapdu_BytesTrailerAndData(b *testing.B) {
	benchmarkRapduBytes(Rapdu{Data: []byte{0x01, 0x02, 0x03, 0x04, 0x05}, SW1: 0x90, SW2: 0x00}, b)
}
